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
use Qiick\Oidc\Services\RpInitiatedLogoutService;
use Qiick\Oidc\Tests\Support\RecordingRoleSynchronization;
use Qiick\Oidc\Tests\Support\User;

/*
 * End to end against a real Keycloak (tests/Fixtures/Keycloak). Excluded from
 * the default run; CI starts Keycloak and runs `pest --group=keycloak` with
 * KEYCLOAK_URL set. Locally:
 *
 *   docker run -d --name laravel-oidc-keycloak -p 8080:8080 \
 *     -v "$PWD/tests/Fixtures/Keycloak:/opt/keycloak/data/import:ro" \
 *     quay.io/keycloak/keycloak:26.2 start-dev --import-realm
 *   KEYCLOAK_URL=http://localhost:8080 vendor/bin/pest --group=keycloak
 *
 * The browser step is played with Guzzle: the Keycloak login form is
 * submitted with the fixture user's password, and the redirect back to the
 * app is followed by the Laravel test client.
 */

const KEYCLOAK_CLIENT_SECRET = 'ci-only-not-a-real-secret';

/**
 * Logs in at the Keycloak login form and returns Keycloak's redirect back to
 * the app (the callback URL), keeping Keycloak's cookies in $cookies.
 */
function loginAtKeycloak(string $authorizationUrl, CookieJar $cookies, string $password = 'ci-only-password'): string
{
    $browser = keycloakBrowser($cookies);
    $loginPage = (string) $browser->get($authorizationUrl)->getBody();

    if (preg_match('/id="kc-form-login"[^>]*action="([^"]+)"/', $loginPage, $matches) !== 1) {
        throw new RuntimeException('Keycloak did not show its login form.');
    }

    $response = $browser->post(html_entity_decode($matches[1]), [
        'form_params' => ['username' => 'ada', 'password' => $password, 'credentialId' => ''],
    ]);

    return $response->getHeaderLine('Location');
}

pest()->group('keycloak');

/**
 * A browser for the Keycloak container. Keycloak marks its cookies Secure even
 * on plain http, where a real browser treats http://localhost as a secure
 * context. Guzzle 7 stores those cookies but does not send them back, and
 * Guzzle 8 does not store them at all (RFC 6265bis). So this client stores
 * every Set-Cookie itself, without the Secure flag.
 */
function keycloakBrowser(CookieJar $cookies): Client
{
    $handlerStack = HandlerStack::create();
    $handlerStack->push(Middleware::mapResponse(function (ResponseInterface $response) use ($cookies): ResponseInterface {
        foreach ($response->getHeader('Set-Cookie') as $setCookieHeader) {
            $cookie = SetCookie::fromString($setCookieHeader);
            $cookie->setSecure(false);
            $cookie->setDomain($cookie->getDomain() ?? 'localhost');
            $cookies->setCookie($cookie);
        }

        return $response;
    }));

    return new Client(['handler' => $handlerStack, 'cookies' => $cookies, 'allow_redirects' => false, 'http_errors' => false]);
}

beforeEach(function (): void {
    $keycloakUrl = getenv('KEYCLOAK_URL');

    if (! is_string($keycloakUrl) || $keycloakUrl === '') {
        $this->markTestSkipped('KEYCLOAK_URL is not set.');
    }

    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', rtrim($keycloakUrl, '/').'/realms/laravel-oidc');
    Config::set('oidc.client_id', 'laravel-app');
    Config::set('oidc.client_secret', KEYCLOAK_CLIENT_SECRET);
    Config::set('oidc.http.allow_private_hosts', true);
    Config::set('oidc.jit', true);
    Config::set('oidc.roles', [
        'enabled' => true,
        'claim' => 'realm_access.roles',
        'organization' => null,
        'map' => ['admin' => 'admin', 'member' => 'editor'],
        'forbidden' => [],
    ]);

    $this->roleSynchronization = new RecordingRoleSynchronization;
    app()->instance(RoleSynchronizationContract::class, $this->roleSynchronization);
    $this->keycloakCookies = new CookieJar;
});

it('signs in end to end: PKCE, state, nonce, RFC 9207 iss, id_token, userinfo, JIT and roles', function (): void {
    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->assertRedirect()->headers->get('Location');
    $callbackUrl = loginAtKeycloak($authorizationUrl, $this->keycloakCookies);

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
        ->and($this->roleSynchronization->calls)->toBe([['granted' => ['editor'], 'managed' => ['admin', 'editor']]])
        ->and(app(IdentitySessionService::class)->current(session()->driver())?->sessionId)->not->toBeNull();
});

it('ends the Keycloak session through RP-initiated logout', function (): void {
    $browser = keycloakBrowser($this->keycloakCookies);
    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->headers->get('Location');
    $this->get(loginAtKeycloak($authorizationUrl, $this->keycloakCookies))->assertRedirect('/');
    $endSessionUrl = (string) app(RpInitiatedLogoutService::class)->endSessionUrl(session()->driver());

    auth()->logout();
    $silentLogin = $browser->get((string) $this->get('/auth/oidc/redirect')->headers->get('Location'));

    expect($silentLogin->getStatusCode())->toBe(302)
        ->and($silentLogin->getHeaderLine('Location'))->toStartWith('http://localhost/auth/oidc/callback?');

    expect($browser->get($endSessionUrl)->getHeaderLine('Location'))->toBe('http://localhost');

    $afterLogout = $browser->get((string) $this->get('/auth/oidc/redirect')->headers->get('Location'));

    expect($afterLogout->getStatusCode())->toBe(200)
        ->and((string) $afterLogout->getBody())->toContain('kc-form-login');
});

it('refuses the login when the client secret is wrong', function (): void {
    Config::set('oidc.client_secret', 'wrong-secret');

    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->headers->get('Location');

    $this->get(loginAtKeycloak($authorizationUrl, $this->keycloakCookies))
        ->assertRedirect('/login')
        ->assertSessionHasErrors(['email' => 'SSO login failed. Try again or use email and password.']);

    expect(auth()->check())->toBeFalse()->and(User::query()->count())->toBe(0);
});

it('passes oidc:configure against Keycloak', function (): void {
    $exitCode = Artisan::call('oidc:configure', ['--json' => true]);
    $report = json_decode(Artisan::output(), true, 512, JSON_THROW_ON_ERROR);

    expect($exitCode)->toBe(0)
        ->and(array_column($report['checks'], 'status', 'check'))->each->toBeIn(['ok', 'warning']);
});
