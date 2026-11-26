<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Factories\OidcOutboundStackFactory;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Services\IdentityProviderHttpService;
use Qiick\Oidc\Tests\Support\OidcSsrfTestGuard;
use Qiick\Outbound\Laravel\OutboundServiceProvider;
use Qiick\Outbound\Testing\FakeHostResolver;

/**
 * Production-container wiring: Outbound must not override OIDC's SSRF / timeouts,
 * and httpsOnly must follow oidc.http.allow_private_hosts from the real provider.
 */
beforeEach(function (): void {
    // Alphabetical discovery would register outbound after OIDC; reproduce that order.
    $this->app->register(OutboundServiceProvider::class);
});

it('refuses a loopback IdP when OutboundServiceProvider registers after OIDC with private hosts open', function (): void {
    Config::set('outbound.ssrf.allow_private_hosts', true);
    Config::set('oidc.http.allow_private_hosts', false);
    Config::set('oidc.http.timeout', 10);
    OidcSsrfTestGuard::bindInContainer(false, ['127.0.0.1']);
    Http::fake(['*' => Http::response(['ok' => true])]);

    expect(fn () => app(IdentityProviderHttpService::class)->getJson('https://127.0.0.1/token'))
        ->toThrow(IdentityProviderRequestException::class, 'private, loopback or metadata address');

    Http::assertNothingSent();
});

it('refuses a hostname that resolves to loopback by default when Outbound opens private hosts', function (): void {
    Config::set('outbound.ssrf.allow_private_hosts', true);
    app()->instance(OidcOutboundStackFactory::HostResolverBinding, new FakeHostResolver(
        answers: ['loopback.idp.test' => ['127.0.0.1']],
    ));
    Http::fake(['*' => Http::response(['ok' => true])]);

    expect(fn () => app(IdentityProviderHttpService::class)->getJson('https://loopback.idp.test/token'))
        ->toThrow(IdentityProviderRequestException::class, 'disallowed address');

    Http::assertNothingSent();
});

it('honours oidc.http.timeout above outbound\'s default max without InvalidArgumentException', function (): void {
    Config::set('outbound.http.max_timeout_seconds', 60);
    Config::set('oidc.http.timeout', 90);
    Config::set('oidc.http.allow_private_hosts', false);
    OidcSsrfTestGuard::bindInContainer(false, ['93.184.216.34']);
    Http::fake(['*' => Http::response(['ok' => true])]);

    $result = null;
    $caughtClass = null;

    try {
        $result = app(IdentityProviderHttpService::class)->getJson('https://idp.example.com/token');
    } catch (Throwable $exception) {
        $caughtClass = $exception::class;
    }

    expect($caughtClass)->toBeNull()
        ->and($result)->toBe(['ok' => true]);
});

it('refuses plain http from the real provider when private hosts are off', function (): void {
    Config::set('oidc.http.allow_private_hosts', false);
    OidcSsrfTestGuard::bindInContainer(false, ['93.184.216.34']);
    Http::fake();

    expect(fn () => app(IdentityProviderHttpService::class)->getJson('http://idp.example.com/token'))
        ->toThrow(IdentityProviderRequestException::class, 'must use https');

    Http::assertNothingSent();
});

it('reaches a private IdP over http when OIDC opts in and shared Outbound stays locked', function (): void {
    Config::set('outbound.ssrf.allow_private_hosts', false);
    Config::set('oidc.http.allow_private_hosts', true);
    app()->instance(OidcOutboundStackFactory::HostResolverBinding, new FakeHostResolver(
        answers: ['keycloak' => ['172.18.0.5']],
    ));
    Http::preventStrayRequests()->fake(['http://keycloak:8080/token' => Http::response(['ok' => true])]);

    expect(app(IdentityProviderHttpService::class)->getJson('http://keycloak:8080/token'))
        ->toBe(['ok' => true]);

    Http::assertSentCount(1);
});

it('refuses browser endpoints with credentials through DiscoveryService from the container', function (): void {
    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', 'https://idp.example.com/realms/test');
    Config::set('oidc.client_id', 'laravel-app');
    Config::set('oidc.http.allow_private_hosts', false);
    OidcSsrfTestGuard::bindInContainer(false, ['93.184.216.34']);
    Http::fake([
        'https://idp.example.com/realms/test/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://idp.example.com/realms/test',
            'authorization_endpoint' => 'https://user:secret@idp.example.com/realms/test/auth',
            'token_endpoint' => 'https://idp.example.com/realms/test/token',
            'jwks_uri' => 'https://idp.example.com/realms/test/jwks',
            'response_types_supported' => ['code'],
            'code_challenge_methods_supported' => ['S256'],
        ]),
    ]);

    expect(fn () => app(DiscoveryService::class)->discover(app(ProviderConfigurationRepositoryContract::class)->configuration()))
        ->toThrow(IdentityProviderRequestException::class, 'must not contain credentials');
});

it('maps timeout 0 to the unlimited ceiling', function (): void {
    expect(IdentityProviderHttpService::resolveTimeoutSeconds(0))
        ->toBe(86_400)
        ->and(IdentityProviderHttpService::resolveTimeoutSeconds(10))->toBe(10);
});

it('raises the private outbound ceilings to at least the configured hop timeouts', function (): void {
    Config::set('outbound.http.max_timeout_seconds', 60);
    Config::set('outbound.http.max_connect_timeout_seconds', 30);
    Config::set('oidc.http.allow_private_hosts', false);
    OidcSsrfTestGuard::bindInContainer(false, ['93.184.216.34']);
    Http::fake(['*' => Http::response(['ok' => true])]);

    Config::set('oidc.http.timeout', 5);
    Config::set('oidc.http.connect_timeout', 5);
    $lowHopLimits = app(OidcOutboundStackFactory::class)->make()->httpLimits;
    expect($lowHopLimits->maxTimeoutSeconds)->toBe(60)
        ->and($lowHopLimits->maxConnectTimeoutSeconds)->toBe(30)
        ->and($lowHopLimits->totalDeadlineSeconds)->toBe(30);

    Config::set('oidc.http.timeout', 10);
    Config::set('oidc.http.connect_timeout', 10);
    $defaultLimits = app(OidcOutboundStackFactory::class)->make()->httpLimits;
    expect($defaultLimits->maxTimeoutSeconds)->toBe(60)
        ->and($defaultLimits->maxConnectTimeoutSeconds)->toBe(30)
        ->and($defaultLimits->totalDeadlineSeconds)->toBe(30);

    Config::set('oidc.http.timeout', 60);
    Config::set('oidc.http.connect_timeout', 30);
    expect(app(IdentityProviderHttpService::class)->getJson('https://idp.example.com/token'))
        ->toBe(['ok' => true]);

    Config::set('oidc.http.timeout', 90);
    Config::set('oidc.http.connect_timeout', 45);
    $raisedLimits = app(OidcOutboundStackFactory::class)->make()->httpLimits;
    expect($raisedLimits->maxTimeoutSeconds)->toBe(90)
        ->and($raisedLimits->maxConnectTimeoutSeconds)->toBe(45)
        ->and($raisedLimits->totalDeadlineSeconds)->toBe(270)
        ->and(app(IdentityProviderHttpService::class)->getJson('https://idp.example.com/token'))
        ->toBe(['ok' => true]);

    Config::set('oidc.http.timeout', 0);
    Config::set('oidc.http.connect_timeout', 0);
    $unlimitedLimits = app(OidcOutboundStackFactory::class)->make()->httpLimits;
    expect($unlimitedLimits->maxTimeoutSeconds)->toBe(86_400)
        ->and($unlimitedLimits->maxConnectTimeoutSeconds)->toBe(86_400)
        ->and($unlimitedLimits->totalDeadlineSeconds)->toBe(86_400 * 3)
        ->and(app(IdentityProviderHttpService::class)->getJson('https://idp.example.com/token'))
        ->toBe(['ok' => true]);
});

it('maps allow_private_hosts onto httpsOnly and allowPrivateHosts together', function (): void {
    Config::set('oidc.http.allow_private_hosts', false);
    OidcSsrfTestGuard::bindInContainer(false, ['93.184.216.34']);
    $locked = app(OidcOutboundStackFactory::class)->make()->urlGuardOptions;
    expect($locked->httpsOnly)->toBeTrue()
        ->and($locked->allowPrivateHosts)->toBeFalse();

    Config::set('oidc.http.allow_private_hosts', true);
    OidcSsrfTestGuard::bindInContainer(true, ['172.18.0.5']);
    $open = app(OidcOutboundStackFactory::class)->make()->urlGuardOptions;
    expect($open->httpsOnly)->toBeFalse()
        ->and($open->allowPrivateHosts)->toBeTrue();
});

it('refuses a wrong type on the private host resolver binding', function (): void {
    app()->instance(OidcOutboundStackFactory::HostResolverBinding, new stdClass);

    expect(fn () => app(OidcOutboundStackFactory::class)->make())
        ->toThrow(LogicException::class, 'HostResolver');
});
