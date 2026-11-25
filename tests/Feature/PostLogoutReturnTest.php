<?php

declare(strict_types=1);

use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use Qiick\Oidc\Services\RpInitiatedLogoutService;
use Qiick\Oidc\Testing\FakeIdentityProvider;

/*
 * Standards review S7: RP-initiated logout sends a random `state` (OIDC
 * RP-Initiated Logout 1.0 §2) and the package's post-logout return route
 * checks it against a short-lived cookie before redirecting to the app's
 * configured landing page. The app's session is invalidated before the
 * browser comes back, so the state cannot live in the session.
 */

const LOGOUT_STATE_COOKIE = 'oidc_logout_state';

/**
 * The end-session URL for a fresh SSO session, and the state cookie queued
 * while building it.
 *
 * @return array{0: array<string, string>, 1: Symfony\Component\HttpFoundation\Cookie|null}
 */
function endSessionParametersAndCookie(FakeIdentityProvider $identityProvider): array
{
    $endSessionUrl = (string) app(RpInitiatedLogoutService::class)->endSessionUrl(sessionAfterSsoLogin($identityProvider));

    return [queryParameters($endSessionUrl), Cookie::queued(LOGOUT_STATE_COOKIE, null, '/auth/oidc')];
}

it('sends a random state and returns to the package route by default', function (): void {
    [$parameters, $stateCookie] = endSessionParametersAndCookie(FakeIdentityProvider::fake());

    expect($parameters['post_logout_redirect_uri'])->toBe('http://localhost/auth/oidc/logged-out')
        ->and($parameters['state'])->toMatch('/^[A-Za-z0-9_-]{43}$/')
        ->and($stateCookie)->not->toBeNull()
        ->and($stateCookie?->getPath())->toBe('/auth/oidc')
        ->and($stateCookie?->isHttpOnly())->toBeTrue()
        ->and($stateCookie?->getSameSite())->toBe('lax')
        ->and($stateCookie?->isSecure())->toBeFalse()
        ->and($stateCookie?->getExpiresTime())->toBe(Date::now()->addMinutes(10)->getTimestamp());
});

it('marks the state cookie Secure when the return route is https', function (): void {
    URL::forceRootUrl('https://app.example.com');
    URL::forceScheme('https');

    [$parameters, $stateCookie] = endSessionParametersAndCookie(FakeIdentityProvider::fake());

    expect($parameters['post_logout_redirect_uri'])->toBe('https://app.example.com/auth/oidc/logged-out')
        ->and($stateCookie?->isSecure())->toBeTrue();
});

it('scopes the state cookie to the return route of an app served under a sub-path', function (): void {
    URL::forceRootUrl('http://localhost/app');

    $endSessionUrl = (string) app(RpInitiatedLogoutService::class)->endSessionUrl(sessionAfterSsoLogin(FakeIdentityProvider::fake()));

    expect(queryParameters($endSessionUrl)['post_logout_redirect_uri'])->toBe('http://localhost/app/auth/oidc/logged-out')
        ->and(Cookie::queued(LOGOUT_STATE_COOKIE, null, '/app/auth/oidc'))->not->toBeNull();
});

it('throttles the post-logout return route, which logs every unmatched state', function (): void {
    FakeIdentityProvider::fake();

    foreach (range(1, 60) as $attempt) {
        $this->get('/auth/oidc/logged-out')->assertRedirect();
    }

    $this->get('/auth/oidc/logged-out')->assertTooManyRequests();
});

it('sends no state and sets no cookie when the app configures its own post-logout uri', function (): void {
    [$parameters, $stateCookie] = endSessionParametersAndCookie(FakeIdentityProvider::fake(configOverrides: ['post_logout_redirect_uri' => 'https://app.example.com/login']));

    expect($parameters)->not->toHaveKey('state')
        ->and($parameters['post_logout_redirect_uri'])->toBe('https://app.example.com/login')
        ->and($stateCookie)->toBeNull();
});

it('redirects to the configured landing page when the state matches, and drops the cookie', function (): void {
    Log::spy();
    [$parameters, $stateCookie] = endSessionParametersAndCookie(FakeIdentityProvider::fake(configOverrides: ['logout.redirect_to' => '/goodbye']));

    $this->withCookie(LOGOUT_STATE_COOKIE, (string) $stateCookie?->getValue())
        ->get('/auth/oidc/logged-out?state='.$parameters['state'])
        ->assertRedirect('/goodbye')
        ->assertCookieExpired(LOGOUT_STATE_COOKIE);

    Log::shouldNotHaveReceived('warning');
});

it('still redirects, with a warning, when the state does not check out', function (string $case): void {
    Log::spy();
    [$parameters, $stateCookie] = endSessionParametersAndCookie(FakeIdentityProvider::fake());
    $cookieValue = $case === 'cookie missing' ? null : (string) $stateCookie?->getValue();
    $returnedState = match ($case) {
        'state missing' => null,
        'state wrong' => 'forged',
        default => $parameters['state'],
    };

    if ($case === 'cookie expired') {
        Date::setTestNow(Date::now()->addMinutes(10)->addSecond());
    }

    $request = $cookieValue === null ? $this : $this->withCookie(LOGOUT_STATE_COOKIE, $cookieValue);

    $request->get('/auth/oidc/logged-out'.($returnedState === null ? '' : '?state='.$returnedState))->assertRedirect('/');

    Log::shouldHaveReceived('warning')->withArgs(fn (string $message): bool => str_contains($message, 'post-logout return without a matching state'));
})->with(['state missing', 'state wrong', 'cookie missing', 'cookie expired']);

it('redirects to / with a config published before S7, which has no logout key', function (): void {
    [$parameters, $stateCookie] = endSessionParametersAndCookie(FakeIdentityProvider::fake());
    Config::set('oidc.logout', null);

    $this->withCookie(LOGOUT_STATE_COOKIE, (string) $stateCookie?->getValue())
        ->get('/auth/oidc/logged-out?state='.$parameters['state'])
        ->assertRedirect('/');
});

it('answers 404 while SSO is off', function (): void {
    Config::set('oidc.enabled', false);

    $this->get('/auth/oidc/logged-out')->assertNotFound();
});

it('accepts the state until the end of its tenth minute', function (): void {
    Log::spy();
    Date::setTestNow(Date::now()->startOfSecond());
    [$parameters, $stateCookie] = endSessionParametersAndCookie(FakeIdentityProvider::fake());
    Date::setTestNow(Date::now()->addMinutes(10));

    $this->withCookie(LOGOUT_STATE_COOKIE, (string) $stateCookie?->getValue())
        ->get('/auth/oidc/logged-out?state='.$parameters['state'])
        ->assertRedirect('/');

    Log::shouldNotHaveReceived('warning');
});

it('refuses a cookie whose expiry is not a number, even with the right state', function (): void {
    Log::spy();
    [$parameters] = endSessionParametersAndCookie(FakeIdentityProvider::fake());

    $this->withCookie(LOGOUT_STATE_COOKIE, 'forever.'.$parameters['state'])
        ->get('/auth/oidc/logged-out?state='.$parameters['state'])
        ->assertRedirect('/');

    Log::shouldHaveReceived('warning');
});

it('sends no state when the app left the return route out', function (): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['redirect_uri' => 'http://localhost/auth/oidc/callback']);
    $session = sessionAfterSsoLogin($identityProvider);
    Route::setRoutes(new RouteCollection);

    $parameters = queryParameters((string) app(RpInitiatedLogoutService::class)->endSessionUrl($session));

    expect($parameters['post_logout_redirect_uri'])->toBe('http://localhost')
        ->and($parameters)->not->toHaveKey('state');
});

it('scopes the cookie to the route prefix however it is written', function (): void {
    Config::set('oidc.routes.prefix', '/auth/oidc/');

    [, $stateCookie] = endSessionParametersAndCookie(FakeIdentityProvider::fake());

    expect($stateCookie?->getPath())->toBe('/auth/oidc');
});
