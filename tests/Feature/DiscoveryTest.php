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

it('strips a trailing slash from the issuer when building the discovery URL', function (): void {
    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', 'https://idp.example.com/realms/test/');
    Config::set('oidc.client_id', 'laravel-app');

    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();

    expect(app(DiscoveryService::class)->discoveryUrl($configuration))
        ->toBe('https://idp.example.com/realms/test/.well-known/openid-configuration');
});

it('builds discovery cache keys with a stable prefix and distinct hashes', function (): void {
    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', 'https://idp.example.com/realms/a');
    Config::set('oidc.client_id', 'laravel-app');
    Config::set('oidc.http.discovery_base', null);
    Config::set('oidc.http.server_origin', null);

    $discovery = app(DiscoveryService::class);
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
    $cacheKeyMethod = new ReflectionMethod(DiscoveryService::class, 'cacheKey');

    $alphaKey = $cacheKeyMethod->invoke($discovery, $configuration);
    expect($alphaKey)->toStartWith('oidc:discovery:')
        ->and(strlen($alphaKey))->toBe(strlen('oidc:discovery:') + 64);

    Config::set('oidc.issuer', 'https://idp.example.com/realms/ab');
    $alphabetKey = $cacheKeyMethod->invoke(
        app(DiscoveryService::class),
        app(ProviderConfigurationRepositoryContract::class)->configuration(),
    );
    expect($alphabetKey)->toStartWith('oidc:discovery:')
        ->and($alphabetKey)->not->toBe($alphaKey);
});

it('separates issuer and discovery_base with NUL so the same characters split differently do not collide', function (): void {
    Config::set('oidc.enabled', true);
    Config::set('oidc.client_id', 'laravel-app');
    Config::set('oidc.http.server_origin', null);

    $cacheKeyMethod = new ReflectionMethod(DiscoveryService::class, 'cacheKey');

    // Without a separator, issuer "…/ab" + base "c" and issuer "…/a" + base "bc" are the same string.
    Config::set('oidc.issuer', 'https://idp.example.com/ab');
    Config::set('oidc.http.discovery_base', 'c');
    $splitAfterAb = $cacheKeyMethod->invoke(
        app(DiscoveryService::class),
        app(ProviderConfigurationRepositoryContract::class)->configuration(),
    );

    Config::set('oidc.issuer', 'https://idp.example.com/a');
    Config::set('oidc.http.discovery_base', 'bc');
    $splitAfterA = $cacheKeyMethod->invoke(
        app(DiscoveryService::class),
        app(ProviderConfigurationRepositoryContract::class)->configuration(),
    );

    expect($splitAfterAb)->not->toBe($splitAfterA)
        ->and($splitAfterAb)->toStartWith('oidc:discovery:')
        ->and($splitAfterA)->toStartWith('oidc:discovery:');
});

it('strips a trailing slash from the discovery base and server origin', function (): void {
    $identityProvider = new FakeIdentityProvider(issuer: 'http://localhost:8080/realms/externa');
    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', $identityProvider->issuer);
    Config::set('oidc.client_id', $identityProvider->clientId);
    Config::set('oidc.http.discovery_base', 'http://keycloak:8080/realms/externa/');
    Config::set('oidc.http.server_origin', 'http://keycloak:8080/');
    Config::set('oidc.http.allow_private_hosts', true);
    OidcSsrfTestGuard::bindInContainer(true, ['172.18.0.5']);
    Http::fake(['http://keycloak:8080/realms/externa/.well-known/openid-configuration' => Http::response($identityProvider->discoveryDocument())]);

    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();

    expect(app(DiscoveryService::class)->discoveryUrl($configuration))
        ->toBe('http://keycloak:8080/realms/externa/.well-known/openid-configuration')
        ->and(discover()->tokenEndpoint)->toBe('http://keycloak:8080/realms/externa/protocol/openid-connect/token');
});

it('does not reuse discovery cache across issuers that share a common prefix', function (): void {
    OidcSsrfTestGuard::bindInContainer(false, ['93.184.215.14']);
    Config::set('oidc.enabled', true);
    Config::set('oidc.client_id', 'laravel-app');

    $alphaIssuer = 'https://idp.example.com/realms/a';
    $alphabetIssuer = 'https://idp.example.com/realms/ab';

    Http::fake([
        $alphaIssuer.'/.well-known/openid-configuration' => Http::response([
            'issuer' => $alphaIssuer,
            'authorization_endpoint' => $alphaIssuer.'/auth',
            'token_endpoint' => $alphaIssuer.'/token',
            'jwks_uri' => $alphaIssuer.'/jwks',
            'response_types_supported' => ['code'],
            'code_challenge_methods_supported' => ['S256'],
        ]),
        $alphabetIssuer.'/.well-known/openid-configuration' => Http::response([
            'issuer' => $alphabetIssuer,
            'authorization_endpoint' => $alphabetIssuer.'/auth',
            'token_endpoint' => $alphabetIssuer.'/token',
            'jwks_uri' => $alphabetIssuer.'/jwks',
            'response_types_supported' => ['code'],
            'code_challenge_methods_supported' => ['S256'],
        ]),
    ]);

    Config::set('oidc.issuer', $alphaIssuer);
    expect(discover()->issuer)->toBe($alphaIssuer);

    Config::set('oidc.issuer', $alphabetIssuer);
    expect(discover()->issuer)->toBe($alphabetIssuer);

    Http::assertSentCount(2);
});

it('does not reuse discovery cache when discovery_base changes', function (): void {
    $issuer = 'https://idp.example.com/realms/test';
    $document = [
        'issuer' => $issuer,
        'authorization_endpoint' => $issuer.'/auth',
        'token_endpoint' => $issuer.'/token',
        'jwks_uri' => $issuer.'/jwks',
        'response_types_supported' => ['code'],
        'code_challenge_methods_supported' => ['S256'],
    ];

    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', $issuer);
    Config::set('oidc.client_id', 'laravel-app');
    OidcSsrfTestGuard::bindInContainer(false, ['93.184.215.14']);
    Http::fake([
        $issuer.'/.well-known/openid-configuration' => Http::response($document),
        $issuer.'/via-base/.well-known/openid-configuration' => Http::response($document),
    ]);

    expect(discover()->tokenEndpoint)->toBe($issuer.'/token');

    Config::set('oidc.http.discovery_base', $issuer.'/via-base');
    expect(discover()->tokenEndpoint)->toBe($issuer.'/token');
    Http::assertSentCount(2);
});

it('does not reuse discovery cache when server_origin changes', function (): void {
    $identityProvider = new FakeIdentityProvider(issuer: 'http://localhost:8080/realms/externa');
    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', $identityProvider->issuer);
    Config::set('oidc.client_id', $identityProvider->clientId);
    Config::set('oidc.http.discovery_base', 'http://keycloak:8080/realms/externa');
    Config::set('oidc.http.server_origin', 'http://keycloak:8080');
    Config::set('oidc.http.allow_private_hosts', true);
    OidcSsrfTestGuard::bindInContainer(true, ['172.18.0.5']);
    Http::fake(['http://keycloak:8080/realms/externa/.well-known/openid-configuration' => Http::response($identityProvider->discoveryDocument())]);

    expect(discover()->tokenEndpoint)->toBe('http://keycloak:8080/realms/externa/protocol/openid-connect/token');

    Config::set('oidc.http.server_origin', 'http://keycloak-b:8080');
    expect(discover()->tokenEndpoint)->toBe('http://keycloak-b:8080/realms/externa/protocol/openid-connect/token');
    Http::assertSentCount(2);
});

it('treats empty optional endpoint strings as absent', function (): void {
    FakeIdentityProvider::fake()->withDiscovery([
        'userinfo_endpoint' => '',
        'end_session_endpoint' => '',
    ]);

    $discovery = discover();

    expect($discovery->userinfoEndpoint)->toBeNull()
        ->and($discovery->endSessionEndpoint)->toBeNull();
});

it('defaults signing algorithms to RS256 when the IdP omits them', function (): void {
    FakeIdentityProvider::fake()->withDiscovery([
        'id_token_signing_alg_values_supported' => null,
    ]);

    expect(discover()->idTokenSigningAlgorithms)->toBe(['RS256']);
});

it('keeps only string signing algorithms and reindexes the list', function (): void {
    FakeIdentityProvider::fake()->withDiscovery([
        'id_token_signing_alg_values_supported' => [2 => 'RS256', 3 => 42, 5 => 'ES256'],
    ]);

    expect(discover()->idTokenSigningAlgorithms)->toBe(['RS256', 'ES256']);
});
