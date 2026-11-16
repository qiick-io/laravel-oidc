<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Cookie\SetCookie;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Psr\Http\Message\ResponseInterface;
use Qiick\Oidc\Contracts\RoleSynchronizationContract;
use Qiick\Oidc\Models\UserIdentity;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Services\RemoteUrlGuardService;
use Qiick\Oidc\Services\RpInitiatedLogoutService;
use Qiick\Oidc\Tests\Support\RecordingRoleSynchronization;
use Qiick\Oidc\Tests\Support\User;

/*
 * End to end against a real Zitadel (tests/Fixtures/zitadel). Excluded from
 * the default run; CI starts Zitadel and runs `pest --group=zitadel` with
 * ZITADEL_URL set. Locally:
 *
 *   bash tests/Fixtures/zitadel/prepare.sh
 *   source "${TMPDIR:-/tmp}/laravel-oidc-zitadel-run/env.sh"
 *   vendor/bin/pest --group=zitadel
 *
 * The browser step is played with Guzzle: Zitadel's Login V1 form (login
 * name, then password) is submitted, and the redirect back to the app is
 * followed by the Laravel test client.
 */

pest()->group('zitadel');

/**
/**
 * @return array{
 *     issuer: string,
 *     client_id: string,
 *     client_secret: string,
 *     project_id: string,
 *     role_claim: string,
 *     users: array{ada: array{login_name: string, email: string, password: string}}
 * }
 */
function zitadelCredentials(): array
{
    $credentialsPath = getenv('ZITADEL_CREDENTIALS');

    if (! is_string($credentialsPath) || $credentialsPath === '' || ! is_file($credentialsPath)) {
        throw new RuntimeException('ZITADEL_CREDENTIALS must point at the JSON written by prepare.sh.');
    }

    /** @var array{
     *     issuer: string,
     *     client_id: string,
     *     client_secret: string,
     *     project_id: string,
     *     role_claim: string,
     *     users: array{ada: array{login_name: string, email: string, password: string}}
     * } $credentials
     */
    $credentials = json_decode((string) file_get_contents($credentialsPath), true, 512, JSON_THROW_ON_ERROR);

    return $credentials;
}

/**
 * A browser for the Zitadel container. Zitadel sets Domain=localhost on its
 * cookies; Guzzle's jar often refuses that domain. This client stores every
 * Set-Cookie itself as a host-only cookie without the Secure flag (plain
 * http://localhost is fine for the suite).
 */
function zitadelBrowser(CookieJar $cookies): Client
{
    $handlerStack = HandlerStack::create();
    $handlerStack->push(Middleware::mapResponse(function (ResponseInterface $response) use ($cookies): ResponseInterface {
        foreach ($response->getHeader('Set-Cookie') as $setCookieHeader) {
            $cookie = SetCookie::fromString($setCookieHeader);
            $cookie->setSecure(false);
            $cookie->setDomain(null);
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

/**
 * Logs in at Zitadel Login V1 and returns the app callback URL.
 */
function loginAtZitadel(string $authorizationUrl, CookieJar $cookies, string $loginName, string $password): string
{
    $browser = zitadelBrowser($cookies);
    $authorizeResponse = $browser->get($authorizationUrl);
    $loginLocation = $authorizeResponse->getHeaderLine('Location');

    if ($loginLocation === '') {
        throw new RuntimeException('Zitadel did not redirect to its login UI.');
    }

    $loginUrl = str_starts_with($loginLocation, 'http') ? $loginLocation : rtrim(zitadelCredentials()['issuer'], '/').$loginLocation;
    $loginPage = (string) $browser->get($loginUrl)->getBody();

    if (preg_match('/name="gorilla\.csrf\.Token" value="([^"]+)"/', $loginPage, $csrfMatches) !== 1
        || preg_match('/name="authRequestID" value="([^"]+)"/', $loginPage, $authRequestMatches) !== 1) {
        throw new RuntimeException('Zitadel login name form was missing.');
    }

    $loginNameResponse = $browser->post(rtrim(zitadelCredentials()['issuer'], '/').'/ui/login/loginname', [
        'form_params' => [
            'gorilla.csrf.Token' => html_entity_decode($csrfMatches[1]),
            'authRequestID' => $authRequestMatches[1],
            'loginName' => $loginName,
        ],
    ]);
    $passwordPage = (string) $loginNameResponse->getBody();

    if (preg_match('/name="gorilla\.csrf\.Token" value="([^"]+)"/', $passwordPage, $passwordCsrfMatches) !== 1
        || preg_match('/name="authRequestID" value="([^"]+)"/', $passwordPage, $passwordAuthRequestMatches) !== 1
        || ! str_contains($passwordPage, 'name="password"')) {
        throw new RuntimeException('Zitadel password form was missing.');
    }

    $passwordResponse = $browser->post(rtrim(zitadelCredentials()['issuer'], '/').'/ui/login/password', [
        'form_params' => [
            'gorilla.csrf.Token' => html_entity_decode($passwordCsrfMatches[1]),
            'authRequestID' => $passwordAuthRequestMatches[1],
            'password' => $password,
        ],
    ]);

    $callbackUrl = followZitadelRedirectsToAppCallback($browser, $passwordResponse->getHeaderLine('Location'));

    if (! str_starts_with($callbackUrl, 'http://localhost/auth/oidc/callback?')) {
        throw new RuntimeException('Zitadel did not redirect to the app callback: '.$callbackUrl);
    }

    return $callbackUrl;
}

/**
 * Follows Zitadel's internal authorize/callback hops until the app redirect.
 */
function followZitadelRedirectsToAppCallback(Client $browser, string $location): string
{
    $issuer = rtrim(zitadelCredentials()['issuer'], '/');

    for ($attempt = 0; $attempt < 8; $attempt++) {
        if ($location === '') {
            throw new RuntimeException('Zitadel redirect chain ended without a Location.');
        }

        if (str_starts_with($location, 'http://localhost/auth/oidc/callback')) {
            return $location;
        }

        $url = str_starts_with($location, 'http') ? $location : $issuer.$location;
        $response = $browser->get($url);
        $location = $response->getHeaderLine('Location');

        if ($location === '' && $response->getStatusCode() === 200) {
            $body = (string) $response->getBody();

            // Optional MFA setup prompt when the org policy still offers it.
            if (str_contains($body, '/ui/login/mfa/prompt')
                && preg_match('/name="gorilla\.csrf\.Token" value="([^"]+)"/', $body, $csrfMatches) === 1
                && preg_match('/name="authRequestID" value="([^"]+)"/', $body, $authRequestMatches) === 1) {
                $skipResponse = $browser->post($issuer.'/ui/login/mfa/prompt', [
                    'form_params' => [
                        'gorilla.csrf.Token' => html_entity_decode($csrfMatches[1]),
                        'authRequestID' => $authRequestMatches[1],
                        'skip' => 'true',
                    ],
                ]);
                $location = $skipResponse->getHeaderLine('Location');

                continue;
            }

            throw new RuntimeException('Zitadel stopped on an unexpected page.');
        }
    }

    throw new RuntimeException('Zitadel redirect chain was too long.');
}

beforeEach(function (): void {
    $zitadelUrl = getenv('ZITADEL_URL');

    if (! is_string($zitadelUrl) || $zitadelUrl === '') {
        $this->markTestSkipped('ZITADEL_URL is not set.');
    }

    $credentials = zitadelCredentials();

    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', rtrim($credentials['issuer'], '/'));
    Config::set('oidc.client_id', $credentials['client_id']);
    Config::set('oidc.client_secret', $credentials['client_secret']);
    // Zitadel puts the project id in id_token `aud` when project roles are asserted.
    Config::set('oidc.id_token.trusted_audiences', [$credentials['project_id']]);
    Config::set('oidc.post_logout_redirect_uri', 'http://localhost');
    Config::set('oidc.http.allow_private_hosts', true);
    Config::set('oidc.jit', true);
    Config::set('oidc.roles', [
        'enabled' => true,
        'claim' => $credentials['role_claim'],
        'organization' => null,
        'map' => ['admin' => 'admin', 'member' => 'editor'],
        'forbidden' => [],
    ]);

    // Singleton captures allow_private_hosts at first resolve; rebuild after Config::set.
    app()->forgetInstance(RemoteUrlGuardService::class);

    $this->roleSynchronization = new RecordingRoleSynchronization;
    app()->instance(RoleSynchronizationContract::class, $this->roleSynchronization);
    $this->zitadelCookies = new CookieJar;
    $this->zitadelCredentials = $credentials;
});

it('signs in end to end: PKCE, state, nonce, id_token, userinfo, JIT and roles', function (): void {
    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->assertRedirect()->headers->get('Location');
    $callbackUrl = loginAtZitadel(
        $authorizationUrl,
        $this->zitadelCookies,
        $this->zitadelCredentials['users']['ada']['login_name'],
        $this->zitadelCredentials['users']['ada']['password'],
    );

    expect($callbackUrl)->toStartWith('http://localhost/auth/oidc/callback?')
        ->and(queryParameters($callbackUrl))->toHaveKeys(['code', 'state']);

    $this->get($callbackUrl)->assertRedirect('/')->assertSessionHasNoErrors();

    $user = User::query()->sole();
    $identity = UserIdentity::query()->sole();

    expect(auth()->id())->toBe($user->id)
        ->and($user->email)->toBe('ada@example.com')
        ->and($user->name)->toBe('Ada Lovelace')
        ->and($identity->issuer)->toBe(Config::string('oidc.issuer'))
        ->and($identity->subject)->not->toBe('')
        ->and($this->roleSynchronization->calls)->toBe([['granted' => ['editor'], 'managed' => ['admin', 'editor']]])
        ->and(app(IdentitySessionService::class)->current(session()->driver())?->idToken)->not->toBeNull();
});

it('ends the Zitadel session through RP-initiated logout', function (): void {
    $browser = zitadelBrowser($this->zitadelCookies);
    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->headers->get('Location');
    $this->get(loginAtZitadel(
        $authorizationUrl,
        $this->zitadelCookies,
        $this->zitadelCredentials['users']['ada']['login_name'],
        $this->zitadelCredentials['users']['ada']['password'],
    ))->assertRedirect('/');

    $endSessionUrl = (string) app(RpInitiatedLogoutService::class)->endSessionUrl(session()->driver());

    auth()->logout();

    $silentLogin = $browser->get((string) $this->get('/auth/oidc/redirect')->headers->get('Location'));

    expect($silentLogin->getStatusCode())->toBe(302)
        ->and(followZitadelRedirectsToAppCallback($browser, $silentLogin->getHeaderLine('Location')))
        ->toStartWith('http://localhost/auth/oidc/callback?');

    $logoutResponse = $browser->get($endSessionUrl);
    $logoutLocation = $logoutResponse->getHeaderLine('Location');

    // Zitadel Login V1 hops through /ui/login/logout/*; accept the registered
    // post-logout URI with or without a trailing slash, or the logout-done page.
    for ($attempt = 0; $attempt < 6; $attempt++) {
        if ($logoutLocation === 'http://localhost' || $logoutLocation === 'http://localhost/') {
            break;
        }

        if ($logoutLocation === '') {
            expect((string) $logoutResponse->getBody())->toContain('logout');

            break;
        }

        $logoutUrl = str_starts_with($logoutLocation, 'http')
            ? $logoutLocation
            : rtrim($this->zitadelCredentials['issuer'], '/').$logoutLocation;
        $logoutResponse = $browser->get($logoutUrl);
        $logoutLocation = $logoutResponse->getHeaderLine('Location');
    }

    expect(in_array($logoutLocation, ['http://localhost', 'http://localhost/', ''], true))->toBeTrue();

    // The previous IdP session must no longer complete SSO silently.
    $afterLogout = $browser->get((string) $this->get('/auth/oidc/redirect')->headers->get('Location'));

    expect($afterLogout->getStatusCode())->toBe(302)
        ->and($afterLogout->getHeaderLine('Location'))->toContain('/ui/login/login?authRequestID=')
        ->and(fn () => followZitadelRedirectsToAppCallback($browser, $afterLogout->getHeaderLine('Location')))
        ->toThrow(RuntimeException::class);

    // A fresh browser is also sent to the login-name form.
    $freshBrowser = zitadelBrowser(new CookieJar);
    $freshAuthorize = $freshBrowser->get((string) $this->get('/auth/oidc/redirect')->headers->get('Location'));
    $freshLoginLocation = $freshAuthorize->getHeaderLine('Location');
    $freshLoginUrl = str_starts_with($freshLoginLocation, 'http')
        ? $freshLoginLocation
        : rtrim($this->zitadelCredentials['issuer'], '/').$freshLoginLocation;

    expect((string) $freshBrowser->get($freshLoginUrl)->getBody())->toContain('name="loginName"');
});

it('refuses the login when the client secret is wrong', function (): void {
    Config::set('oidc.client_secret', 'wrong-secret');

    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->headers->get('Location');

    $this->get(loginAtZitadel(
        $authorizationUrl,
        $this->zitadelCookies,
        $this->zitadelCredentials['users']['ada']['login_name'],
        $this->zitadelCredentials['users']['ada']['password'],
    ))
        ->assertRedirect('/login')
        ->assertSessionHasErrors(['email' => 'SSO login failed. Try again or use email and password.']);

    expect(auth()->check())->toBeFalse()->and(User::query()->count())->toBe(0);
});

it('passes oidc:configure against Zitadel', function (): void {
    $exitCode = Artisan::call('oidc:configure', ['--json' => true]);
    $report = json_decode(Artisan::output(), true, 512, JSON_THROW_ON_ERROR);

    expect($exitCode)->toBe(0)
        ->and(array_column($report['checks'], 'status', 'check'))->each->toBeIn(['ok', 'warning']);
});
