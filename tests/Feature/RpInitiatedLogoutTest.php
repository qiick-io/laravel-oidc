<?php

declare(strict_types=1);

use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Config;
use Qiick\Oidc\Services\AuthorizationCodeFlowService;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Services\RpInitiatedLogoutService;
use Qiick\Oidc\Testing\FakeIdentityProvider;

function sessionAfterSsoLogin(FakeIdentityProvider $identityProvider): Session
{
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));
    $identity = app(AuthorizationCodeFlowService::class)->handleCallback(browserRequest($callbackUrl, $session));
    app(IdentitySessionService::class)->remember($session, $identity);

    return $session;
}

it('builds the end session url with id_token_hint, client_id and the post-logout redirect', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $session = sessionAfterSsoLogin($identityProvider);

    $endSessionUrl = (string) app(RpInitiatedLogoutService::class)->endSessionUrl($session);
    $parameters = queryParameters($endSessionUrl);

    expect($endSessionUrl)->toStartWith($identityProvider->issuer.'/protocol/openid-connect/logout?')
        ->and($parameters['id_token_hint'])->toBe(app(IdentitySessionService::class)->current($session)?->idToken)
        ->and($parameters['client_id'])->toBe('laravel-app')
        ->and($parameters['post_logout_redirect_uri'])->toBe('http://localhost/auth/oidc/logged-out');
});

it('uses the configured post-logout redirect uri', function (): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['post_logout_redirect_uri' => 'https://app.example.com/login']);

    $parameters = queryParameters((string) app(RpInitiatedLogoutService::class)->endSessionUrl(sessionAfterSsoLogin($identityProvider)));

    expect($parameters['post_logout_redirect_uri'])->toBe('https://app.example.com/login');
});

it('returns null for a local login', function (): void {
    FakeIdentityProvider::fake();

    expect(app(RpInitiatedLogoutService::class)->endSessionUrl(browserSession()))->toBeNull();
});

it('returns null when the IdP has no end session endpoint, SSO is off or the issuer changed', function (Closure $change): void {
    $identityProvider = FakeIdentityProvider::fake();
    $session = sessionAfterSsoLogin($identityProvider);

    $change($identityProvider);

    expect(app(RpInitiatedLogoutService::class)->endSessionUrl($session))->toBeNull();
})->with([
    'no end_session_endpoint' => fn (FakeIdentityProvider $identityProvider) => $identityProvider->withDiscovery(['end_session_endpoint' => null]) && cache()->flush(),
    'SSO turned off' => fn () => Config::set('oidc.enabled', false),
    'issuer changed' => fn () => Config::set('oidc.issuer', 'https://other-idp.example.com'),
]);

it('forgets the identity on request', function (): void {
    $session = sessionAfterSsoLogin(FakeIdentityProvider::fake());

    app(IdentitySessionService::class)->forget($session);

    expect(app(IdentitySessionService::class)->current($session))->toBeNull();
});
