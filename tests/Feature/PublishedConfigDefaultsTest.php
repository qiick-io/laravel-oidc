<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Config;
use Qiick\Oidc\Factories\OidcOutboundStackFactory;
use Qiick\Oidc\Laravel\OidcServiceProvider;

/*
 * An app that published config/oidc.php before a nested key existed still
 * gets the package default for it: Laravel's mergeConfigFrom() fills only
 * top-level keys, so the service provider merges the defaults into nested
 * arrays itself. Lists stay the app's own choice.
 */

beforeEach(function (): void {
    // A config published by an early beta: no http.connect_timeout, no
    // http.max_response_bytes, a partial mfa array.
    Config::set('oidc', [
        'enabled' => true,
        'issuer' => 'https://idp.example.com/realms/test',
        'client_id' => 'laravel-app',
        'scopes' => ['openid'],
        'http' => ['timeout' => 5],
        'mfa' => ['required' => true],
        'id_token' => ['algorithms' => ['RS384']],
        'roles' => ['map' => ['owner' => 'admin']],
    ]);

    // Boot the provider again, as the app does with that config.
    app()->register(OidcServiceProvider::class, force: true);
});

it('fills nested keys missing from a published config', function (): void {
    expect(config('oidc.http.timeout'))->toBe(5)
        ->and(config('oidc.http.connect_timeout'))->toBe(10)
        ->and(config('oidc.http.max_response_bytes'))->toBe(1_048_576)
        ->and(config('oidc.mfa.required'))->toBeTrue()
        ->and(config('oidc.mfa.amr_values'))->toBe(['mfa'])
        ->and(config('oidc.id_token.leeway'))->toBe(60)
        ->and(config('oidc.cache.jwks_ttl'))->toBe(3600);
});

it('keeps the app lists instead of merging them with the defaults', function (): void {
    expect(config('oidc.scopes'))->toBe(['openid'])
        ->and(config('oidc.id_token.algorithms'))->toBe(['RS384'])
        ->and(config('oidc.roles.map'))->toBe(['owner' => 'admin']);
});

it('builds the outbound stack from a published config without connect_timeout', function (): void {
    $httpLimits = app(OidcOutboundStackFactory::class)->make()->httpLimits;

    expect([$httpLimits->maxTimeoutSeconds, $httpLimits->maxConnectTimeoutSeconds, $httpLimits->totalDeadlineSeconds])->toBe([60, 30, 30]);
});

it('keeps a published scalar where the defaults have an array', function (): void {
    Config::set('oidc.http', 'not-an-array');
    app()->register(OidcServiceProvider::class, force: true);

    expect(config('oidc.http'))->toBe('not-an-array');
});
