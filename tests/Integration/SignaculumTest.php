<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Cookie\SetCookie;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Psr\Http\Message\ResponseInterface;
use Qiick\Oidc\Contracts\RoleSynchronizationContract;
use Qiick\Oidc\Contracts\SecondFactorChallengeContract;
use Qiick\Oidc\Models\UserIdentity;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Services\RpInitiatedLogoutService;
use Qiick\Oidc\Tests\Support\RecordingRoleSynchronization;
use Qiick\Oidc\Tests\Support\User;
use Symfony\Component\HttpFoundation\Response;

/*
 * End to end against a real Signaculum (origin/develop). Excluded from the
 * default run; CI prepares Signaculum and runs `pest --group=signaculum` with
 * SIGNACULUM_URL set. Locally (throwaway worktree, never the Herd site):
 *
 *   git -C ../signaculum-core worktree add /tmp/signaculum-oidc-e2e origin/develop
 *   SIGNACULUM_DIR=/tmp/signaculum-oidc-e2e bash tests/Fixtures/signaculum/prepare.sh
 *   source "${TMPDIR:-/tmp}/laravel-oidc-signaculum-run/env.sh"
 *   php -S 127.0.0.1:${BACKCHANNEL_PORT} tests/Fixtures/signaculum/backchannel-receiver.php &
 *   (cd "${SIGNACULUM_DIR}" && php artisan serve --host=127.0.0.1 --port="${SIGNACULUM_PORT}") &
 *   vendor/bin/pest --group=signaculum
 *
 * The browser step is Guzzle: Fortify login (+ optional TOTP), then the
 * first-party authorize redirect back to the package callback.
 */

pest()->group('signaculum');

/**
 * @return array{
 *   issuer: string,
 *   client_id: string,
 *   client_secret: string,
 *   organization_slug: string,
 *   users: array{ada: array{email: string, password: string}, mfa: array{email: string, password: string, totp_secret: string}}
 * }
 */
function signaculumCredentials(): array
{
    $path = getenv('SIGNACULUM_CREDENTIALS');

    if (is_string($path) && $path !== '' && is_file($path)) {
        /** @var array{issuer: string, client_id: string, client_secret: string, organization_slug: string, users: array{ada: array{email: string, password: string}, mfa: array{email: string, password: string, totp_secret: string}}} $credentials */
        $credentials = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

        return $credentials;
    }

    $issuer = getenv('SIGNACULUM_URL');
    $clientId = getenv('SIGNACULUM_CLIENT_ID');
    $clientSecret = getenv('SIGNACULUM_CLIENT_SECRET');
    $organizationSlug = getenv('SIGNACULUM_ORG_SLUG') ?: 'acme';
    $totpSecret = getenv('SIGNACULUM_TOTP_SECRET');

    if (! is_string($issuer) || $issuer === '' || ! is_string($clientId) || $clientId === '' || ! is_string($clientSecret) || $clientSecret === '') {
        throw new RuntimeException('Signaculum credentials are missing (SIGNACULUM_CREDENTIALS or SIGNACULUM_URL/CLIENT_ID/CLIENT_SECRET).');
    }

    return [
        'issuer' => rtrim($issuer, '/'),
        'client_id' => $clientId,
        'client_secret' => $clientSecret,
        'organization_slug' => is_string($organizationSlug) ? $organizationSlug : 'acme',
        'users' => [
            'ada' => ['email' => 'ada@example.com', 'password' => 'password'],
            'mfa' => [
                'email' => 'mfa@example.com',
                'password' => 'password',
                'totp_secret' => is_string($totpSecret) ? $totpSecret : '',
            ],
        ],
    ];
}

/**
 * RFC 6238 TOTP (SHA-1, 30 s, 6 digits). Avoids adding pragmarx/google2fa to the package.
 */
function signaculumTotp(string $secret, ?int $timestamp = null): string
{
    $timestamp ??= time();
    $counter = intdiv($timestamp, 30);
    $normalizedSecret = strtoupper($secret);
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';

    foreach (str_split($normalizedSecret) as $character) {
        $value = strpos($alphabet, $character);

        if ($value === false) {
            continue;
        }

        $bits .= str_pad(decbin($value), 5, '0', STR_PAD_LEFT);
    }

    $binarySecret = '';

    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) {
            $binarySecret .= chr((int) bindec($byte));
        }
    }

    $hash = hash_hmac('sha1', pack('N*', 0, $counter), $binarySecret, true);
    $offset = ord($hash[19]) & 0x0F;
    $code = (
        ((ord($hash[$offset]) & 0x7F) << 24)
        | ((ord($hash[$offset + 1]) & 0xFF) << 16)
        | ((ord($hash[$offset + 2]) & 0xFF) << 8)
        | (ord($hash[$offset + 3]) & 0xFF)
    ) % 1_000_000;

    return str_pad((string) $code, 6, '0', STR_PAD_LEFT);
}

/**
 * App second factor that always challenges, so MFA via IdP `amr`/`acr` is the only pass path.
 */
function bindSignaculumAppSecondFactor(): void
{
    app()->instance(SecondFactorChallengeContract::class, new readonly class implements SecondFactorChallengeContract
    {
        public function isRequired(Model&Authenticatable $user): bool
        {
            return true;
        }

        public function challenge(Request $request, Model&Authenticatable $user, bool $shouldRemember): ?Response
        {
            $request->session()->put('login.id', $user->getKey());

            return new RedirectResponse('/two-factor-challenge');
        }
    });
}

function disableSignaculumAppSecondFactor(): void
{
    Config::set('oidc.mfa.required', false);
    app()->instance(SecondFactorChallengeContract::class, new readonly class implements SecondFactorChallengeContract
    {
        public function isRequired(Model&Authenticatable $user): bool
        {
            return false;
        }

        public function challenge(Request $request, Model&Authenticatable $user, bool $shouldRemember): ?Response
        {
            return null;
        }
    });
}

/**
 * A browser for Signaculum. Same Secure-cookie workaround as the Keycloak job.
 */
function signaculumBrowser(CookieJar $cookies): Client
{
    $handlerStack = HandlerStack::create();
    $handlerStack->push(Middleware::mapResponse(function (ResponseInterface $response) use ($cookies): ResponseInterface {
        foreach ($response->getHeader('Set-Cookie') as $setCookieHeader) {
            $cookie = SetCookie::fromString($setCookieHeader);
            $cookie->setSecure(false);
            $cookie->setDomain($cookie->getDomain() ?? '127.0.0.1');
            $cookies->setCookie($cookie);
        }

        return $response;
    }));

    return new Client([
        'handler' => $handlerStack,
        'cookies' => $cookies,
        'allow_redirects' => false,
        'http_errors' => false,
    ]);
}

function signaculumXsrfToken(CookieJar $cookies): string
{
    $cookie = $cookies->getCookieByName('XSRF-TOKEN');

    if ($cookie === null) {
        throw new RuntimeException('Signaculum did not set an XSRF-TOKEN cookie.');
    }

    return urldecode($cookie->getValue() ?? '');
}

function absoluteSignaculumUrl(string $location, string $currentUrl): string
{
    if (str_starts_with($location, 'http://') || str_starts_with($location, 'https://')) {
        return $location;
    }

    $parts = parse_url($currentUrl);
    $origin = ($parts['scheme'] ?? 'http').'://'.($parts['host'] ?? '127.0.0.1');

    if (isset($parts['port'])) {
        $origin .= ':'.$parts['port'];
    }

    return str_starts_with($location, '/') ? $origin.$location : $origin.'/'.$location;
}

/**
 * Follow Signaculum redirects until the app callback, the registered
 * post-logout URI, or a non-redirect response.
 *
 * The post-logout URI is `http://localhost/` and nothing listens on :80 in CI,
 * so following that Location is a ConnectException, not a signal. Stop when the
 * Location is that URI (with or without a trailing slash), the same way the
 * Keycloak and Zitadel suites only assert the Location header.
 *
 * @return array{status: int, location: string, body: string, final_url: string}
 */
function followSignaculumRedirects(Client $browser, string $url, int $maximumHops = 12): array
{
    $currentUrl = $url;

    for ($hop = 0; $hop < $maximumHops; $hop++) {
        $response = $browser->get($currentUrl);
        $status = $response->getStatusCode();
        $location = $response->getHeaderLine('Location');

        if ($status < 300 || $status >= 400 || $location === '') {
            return [
                'status' => $status,
                'location' => $location,
                'body' => (string) $response->getBody(),
                'final_url' => $currentUrl,
            ];
        }

        $absoluteLocation = absoluteSignaculumUrl($location, $currentUrl);

        if (str_starts_with($absoluteLocation, 'http://localhost/auth/oidc/callback')) {
            return [
                'status' => $status,
                'location' => $absoluteLocation,
                'body' => (string) $response->getBody(),
                'final_url' => $currentUrl,
            ];
        }

        // Registered post_logout_redirect_uri — do not GET localhost:80.
        if ($absoluteLocation === 'http://localhost' || $absoluteLocation === 'http://localhost/') {
            return [
                'status' => $status,
                'location' => $absoluteLocation,
                'body' => (string) $response->getBody(),
                'final_url' => $currentUrl,
            ];
        }

        $currentUrl = $absoluteLocation;
    }

    throw new RuntimeException('Signaculum redirect loop while following '.$url);
}

/**
 * Log in at Signaculum (password, optional TOTP) and return the package callback URL.
 */
function loginAtSignaculum(
    string $authorizationUrl,
    CookieJar $cookies,
    string $email,
    string $password,
    ?string $totpSecret = null,
): string {
    $browser = signaculumBrowser($cookies);
    $issuer = rtrim(signaculumCredentials()['issuer'], '/');
    $afterAuthorize = followSignaculumRedirects($browser, $authorizationUrl);

    if (str_starts_with($afterAuthorize['location'], 'http://localhost/auth/oidc/callback')) {
        return $afterAuthorize['location'];
    }

    $browser->get($issuer.'/login');
    $xsrfToken = signaculumXsrfToken($cookies);
    $loginResponse = $browser->post($issuer.'/login', [
        'headers' => [
            'X-XSRF-TOKEN' => $xsrfToken,
            'Accept' => 'text/html, application/xhtml+xml',
            'Referer' => $issuer.'/login',
        ],
        'form_params' => [
            'email' => $email,
            'password' => $password,
        ],
    ]);

    $nextLocation = $loginResponse->getHeaderLine('Location');

    if ($totpSecret !== null && $totpSecret !== '') {
        $challengeUrl = $nextLocation !== ''
            ? absoluteSignaculumUrl($nextLocation, $issuer.'/login')
            : $issuer.'/two-factor-challenge';

        $browser->get($challengeUrl);
        $xsrfToken = signaculumXsrfToken($cookies);
        $challengeResponse = $browser->post($issuer.'/two-factor-challenge', [
            'headers' => [
                'X-XSRF-TOKEN' => $xsrfToken,
                'Accept' => 'text/html, application/xhtml+xml',
                'Referer' => $issuer.'/two-factor-challenge',
            ],
            'form_params' => [
                'code' => signaculumTotp($totpSecret),
            ],
        ]);
        $nextLocation = $challengeResponse->getHeaderLine('Location');
    }

    if ($nextLocation === '') {
        throw new RuntimeException(
            'Signaculum login did not redirect (status '.$loginResponse->getStatusCode().'): '
            .substr((string) $loginResponse->getBody(), 0, 400),
        );
    }

    $afterLogin = followSignaculumRedirects($browser, absoluteSignaculumUrl($nextLocation, $issuer.'/login'));

    if (! str_starts_with($afterLogin['location'], 'http://localhost/auth/oidc/callback')) {
        $afterLogin = followSignaculumRedirects($browser, $authorizationUrl);
    }

    if (! str_starts_with($afterLogin['location'], 'http://localhost/auth/oidc/callback')) {
        throw new RuntimeException(
            'Signaculum did not redirect to the package callback. Last location: '
            .$afterLogin['location'].' body: '.substr($afterLogin['body'], 0, 500),
        );
    }

    return $afterLogin['location'];
}

beforeEach(function (): void {
    $signaculumUrl = getenv('SIGNACULUM_URL');

    if (! is_string($signaculumUrl) || $signaculumUrl === '') {
        $this->markTestSkipped('SIGNACULUM_URL is not set.');
    }

    $credentials = signaculumCredentials();

    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', $credentials['issuer']);
    Config::set('oidc.client_id', $credentials['client_id']);
    Config::set('oidc.client_secret', $credentials['client_secret']);
    Config::set('oidc.http.allow_private_hosts', true);
    Config::set('oidc.jit', true);
    Config::set('oidc.scopes', ['openid', 'profile', 'email', 'qiick.orgs']);
    Config::set('oidc.userinfo', true);
    Config::set('oidc.post_logout_redirect_uri', 'http://localhost/');
    Config::set('oidc.roles', [
        'enabled' => true,
        'claim' => 'orgs',
        'organization' => $credentials['organization_slug'],
        'map' => [
            'admin' => 'admin',
            'member' => 'editor',
            'owner' => 'admin',
        ],
        'forbidden' => [],
    ]);
    Config::set('oidc.mfa', [
        'required' => true,
        'trust_provider' => true,
        'amr_values' => ['mfa'],
        'acr_values' => ['urn:qiick:loa:mfa'],
        'request_acr_values' => null,
    ]);

    Route::middleware('web')->get('/probe', fn () => auth()->check() ? 'signed-in' : 'guest');

    $this->roleSynchronization = new RecordingRoleSynchronization;
    app()->instance(RoleSynchronizationContract::class, $this->roleSynchronization);
    $this->signaculumCookies = new CookieJar;
    $this->signaculumCredentials = $credentials;
});

it('signs in end to end: PKCE, state, nonce, RFC 9207 iss, id_token, userinfo, JIT and orgs roles', function (): void {
    disableSignaculumAppSecondFactor();

    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->assertRedirect()->headers->get('Location');
    $callbackUrl = loginAtSignaculum(
        $authorizationUrl,
        $this->signaculumCookies,
        $this->signaculumCredentials['users']['ada']['email'],
        $this->signaculumCredentials['users']['ada']['password'],
    );

    expect($callbackUrl)->toStartWith('http://localhost/auth/oidc/callback?')
        ->and(queryParameters($callbackUrl))->toHaveKeys(['code', 'state', 'iss']);

    $this->get($callbackUrl)->assertRedirect('/')->assertSessionHasNoErrors();

    $user = User::query()->sole();
    $identity = UserIdentity::query()->sole();

    expect(auth()->id())->toBe($user->id)
        ->and($user->email)->toBe('ada@example.com')
        ->and($user->name)->toBe('Ada Lovelace')
        ->and($identity->issuer)->toBe(Config::string('oidc.issuer'))
        ->and($identity->subject)->toMatch('/^[0-9a-f-]{36}$/')
        ->and($this->roleSynchronization->calls)->toBe([['granted' => ['admin', 'editor'], 'managed' => ['admin', 'editor']]])
        ->and(app(IdentitySessionService::class)->current(session()->driver())?->sessionId)->not->toBeNull();
});

it('accepts MFA proven by Signaculum amr and skips the app second factor', function (): void {
    bindSignaculumAppSecondFactor();

    $totpSecret = $this->signaculumCredentials['users']['mfa']['totp_secret'] ?? '';

    expect($totpSecret)->not->toBe('');

    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->assertRedirect()->headers->get('Location');
    $callbackUrl = loginAtSignaculum(
        $authorizationUrl,
        $this->signaculumCookies,
        $this->signaculumCredentials['users']['mfa']['email'],
        $this->signaculumCredentials['users']['mfa']['password'],
        $totpSecret,
    );

    $this->get($callbackUrl)->assertRedirect('/')->assertSessionHasNoErrors();

    expect(auth()->check())->toBeTrue()
        ->and(User::query()->sole()->email)->toBe('mfa@example.com')
        ->and(session('login.id'))->toBeNull();
});

it('ends the Signaculum session through RP-initiated logout and consumes a back-channel logout_token', function (): void {
    disableSignaculumAppSecondFactor();

    $capturePath = getenv('SIGNACULUM_BACKCHANNEL_CAPTURE') ?: sys_get_temp_dir().'/laravel-oidc-signaculum-logout-token.txt';
    @unlink($capturePath);

    $browser = signaculumBrowser($this->signaculumCookies);
    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->headers->get('Location');
    $this->get(loginAtSignaculum(
        $authorizationUrl,
        $this->signaculumCookies,
        $this->signaculumCredentials['users']['ada']['email'],
        $this->signaculumCredentials['users']['ada']['password'],
    ))->assertRedirect('/');

    expect(app(IdentitySessionService::class)->current(session()->driver())?->sessionId)->not->toBeNull();

    $endSessionUrl = (string) app(RpInitiatedLogoutService::class)->endSessionUrl(session()->driver());

    $logoutResponse = followSignaculumRedirects($browser, $endSessionUrl);
    $postLogoutLocation = $logoutResponse['location'] !== '' ? $logoutResponse['location'] : $logoutResponse['final_url'];

    expect($postLogoutLocation)->toMatch('#^http://localhost/?$#');

    $deadline = time() + 20;

    while (time() < $deadline && ! is_file($capturePath)) {
        usleep(200_000);
    }

    expect(is_file($capturePath))->toBeTrue('Signaculum did not POST a logout_token to the back-channel receiver at '.$capturePath);

    $logoutToken = trim((string) file_get_contents($capturePath));
    expect($logoutToken)->not->toBe('');

    $this->post('/auth/oidc/backchannel-logout', ['logout_token' => $logoutToken])->assertOk();

    $this->get('/probe')->assertSeeText('guest');

    $freshCookies = new CookieJar;
    $freshBrowser = signaculumBrowser($freshCookies);
    $afterIdpLogout = followSignaculumRedirects(
        $freshBrowser,
        (string) $this->get('/auth/oidc/redirect')->headers->get('Location'),
    );

    expect($afterIdpLogout['final_url'].' '.$afterIdpLogout['location'].' '.$afterIdpLogout['body'])
        ->toMatch('/login|Log in|email/i');
});

it('passes oidc:configure against Signaculum', function (): void {
    $exitCode = Artisan::call('oidc:configure', ['--json' => true]);
    $report = json_decode(Artisan::output(), true, 512, JSON_THROW_ON_ERROR);

    expect($exitCode)->toBe(0)
        ->and(array_column($report['checks'], 'status', 'check'))->each->toBeIn(['ok', 'warning']);
});
