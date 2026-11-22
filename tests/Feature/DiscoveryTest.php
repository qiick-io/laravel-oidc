<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Data\DiscoveryDocumentData;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Testing\FakeIdentityProvider;
use Qiick\Oidc\Tests\Support\OidcSsrfTestGuard;

function discover(): DiscoveryDocumentData
{
    return app(DiscoveryService::class)->discover(app(ProviderConfigurationRepositoryContract::class)->configuration());
}

it('reads the endpoints from the discovery document', function (): void {
    $identityProvider = FakeIdentityProvider::fake();

    $discovery = discover();

    expect($discovery->issuer)->toBe($identityProvider->issuer)
        ->and($discovery->authorizationEndpoint)->toBe($identityProvider->issuer.'/protocol/openid-connect/auth')
        ->and($discovery->tokenEndpoint)->toBe($identityProvider->issuer.'/protocol/openid-connect/token')
        ->and($discovery->jwksUri)->toBe($identityProvider->issuer.'/protocol/openid-connect/certs')
        ->and($discovery->userinfoEndpoint)->toBe($identityProvider->issuer.'/protocol/openid-connect/userinfo')
        ->and($discovery->endSessionEndpoint)->toBe($identityProvider->issuer.'/protocol/openid-connect/logout')
        ->and($discovery->idTokenSigningAlgorithms)->toBe(['RS256']);
});

it('caches the document and forgets it on request', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();

    discover();
    discover();
    expect($identityProvider->discoveryRequestCount)->toBe(1);

    app(DiscoveryService::class)->forget($configuration);
    discover();
    expect($identityProvider->discoveryRequestCount)->toBe(2);
});

it('refuses a document whose issuer differs from the configured one', function (string $publishedIssuer): void {
    FakeIdentityProvider::fake()->withDiscovery(['issuer' => $publishedIssuer]);

    discover();
})->throws(IdentityProviderRequestException::class, 'does not match the configured issuer')->with([
    'another issuer' => 'https://evil.example.com/realms/test',
    'trailing slash' => 'https://idp.example.com/realms/test/',
]);

it('refuses a document without a required endpoint', function (string $missingKey): void {
    FakeIdentityProvider::fake()->withDiscovery([$missingKey => null]);

    discover();
})->throws(IdentityProviderRequestException::class, 'has no')->with(['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri']);

it('refuses an IdP without the code flow or without PKCE S256', function (array $overrides): void {
    FakeIdentityProvider::fake()->withDiscovery($overrides);

    discover();
})->throws(IdentityProviderRequestException::class)->with([
    'implicit only' => [['response_types_supported' => ['id_token']]],
    'plain PKCE only' => [['code_challenge_methods_supported' => ['plain']]],
]);

it('accepts an IdP that does not list PKCE methods', function (): void {
    FakeIdentityProvider::fake()->withDiscovery(['code_challenge_methods_supported' => null]);

    expect(discover()->tokenEndpoint)->toEndWith('/token');
});

it('refuses browser endpoints with an unsafe scheme', function (string $endpoint): void {
    FakeIdentityProvider::fake()->withDiscovery([$endpoint => 'javascript:alert(1)']);

    discover();
})->throws(IdentityProviderRequestException::class)->with(['authorization_endpoint', 'end_session_endpoint']);

it('refuses a discovery url on a private network without the opt-in', function (): void {
    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', 'https://10.0.0.5/realms/test');
    Config::set('oidc.client_id', 'laravel-app');
    Http::fake();

    discover();
})->throws(IdentityProviderRequestException::class, 'not allowed');

it('surfaces an HTTP error without the response body', function (): void {
    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', 'https://idp.example.com/realms/test');
    Config::set('oidc.client_id', 'laravel-app');
    OidcSsrfTestGuard::bindInContainer(false, ['93.184.215.14']);
    Http::fake(['*' => Http::response('<html>secret stack trace</html>', 500)]);

    expect(fn () => discover())->toThrow(
        fn (IdentityProviderRequestException $exception) => expect($exception->getMessage())
            ->toBe('OIDC request to [idp.example.com] failed with HTTP 500.')
    );
});

it('does not follow redirects', function (): void {
    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', 'https://idp.example.com/realms/test');
    Config::set('oidc.client_id', 'laravel-app');
    OidcSsrfTestGuard::bindInContainer(false, ['93.184.215.14']);
    Http::fake(['*' => Http::response('', 302, ['Location' => 'http://169.254.169.254/'])]);

    discover();
})->throws(IdentityProviderRequestException::class, 'HTTP 302');

it('fetches from the docker base and rewrites only the server-side endpoints', function (): void {
    $identityProvider = new FakeIdentityProvider(issuer: 'http://localhost:8080/realms/externa');
    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', $identityProvider->issuer);
    Config::set('oidc.client_id', $identityProvider->clientId);
    Config::set('oidc.http.discovery_base', 'http://keycloak:8080/realms/externa');
    Config::set('oidc.http.server_origin', 'http://keycloak:8080');
    Config::set('oidc.http.allow_private_hosts', true);
    OidcSsrfTestGuard::bindInContainer(true, ['172.18.0.5']);
    Http::fake(['http://keycloak:8080/realms/externa/.well-known/openid-configuration' => Http::response($identityProvider->discoveryDocument())]);

    $discovery = discover();

    expect($discovery->issuer)->toBe('http://localhost:8080/realms/externa')
        ->and($discovery->authorizationEndpoint)->toBe('http://localhost:8080/realms/externa/protocol/openid-connect/auth')
        ->and($discovery->endSessionEndpoint)->toBe('http://localhost:8080/realms/externa/protocol/openid-connect/logout')
        ->and($discovery->tokenEndpoint)->toBe('http://keycloak:8080/realms/externa/protocol/openid-connect/token')
        ->and($discovery->jwksUri)->toBe('http://keycloak:8080/realms/externa/protocol/openid-connect/certs')
        ->and($discovery->userinfoEndpoint)->toBe('http://keycloak:8080/realms/externa/protocol/openid-connect/userinfo');
});
