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
        ->and(config('oidc.mfa.trust_provider'))->toBeFalse()
        ->and(config('oidc.mfa.amr_values'))->toBe([])
        ->and(config('oidc.id_token.leeway'))->toBe(60)
        ->and(config('oidc.cache.jwks_ttl'))->toBe(3600)
        ->and(config('oidc.backchannel_logout.rate_limit'))->toBe(600)
        ->and(config('oidc.backchannel_logout.max_retention_seconds'))->toBe(2_592_000);
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

it('fills an empty published section while keeping explicitly empty lists and null overrides', function (): void {
    Config::set('oidc.http', []);
    Config::set('oidc.cache', ['store' => null]);
    Config::set('oidc.break_glass.roles', []);
    app()->register(OidcServiceProvider::class, force: true);

    expect(config('oidc.http.connect_timeout'))->toBe(10)
        ->and(config('oidc.cache.store'))->toBeNull()
        ->and(config('oidc.cache.jwks_ttl'))->toBe(3600)
        ->and(config('oidc.break_glass.roles'))->toBe([]);
});

it('fills missing nested keys from an older configuration cache', function (): void {
    app()->instance('config_loaded_from_cache', true);
    Config::set('oidc.http', ['timeout' => 7]);
    app()->register(OidcServiceProvider::class, force: true);

    expect(config('oidc.http.timeout'))->toBe(7)
        ->and(config('oidc.http.connect_timeout'))->toBe(10);
});

it('accepts configured zero, nullable values and replacement lists without normalising them at boot', function (): void {
    Config::set([
        'oidc.http.timeout' => 0,
        'oidc.http.max_response_bytes' => 1,
        'oidc.mfa.max_age' => '0',
        'oidc.backchannel_logout.revocation_ttl' => 0,
        'oidc.token_endpoint_auth_method' => ' client_secret_post ',
        'oidc.roles.map' => ['maintainer' => ['editor', 'viewer']],
        'oidc.routes.except' => [],
    ]);

    expect(app()->register(OidcServiceProvider::class, force: true))->toBeInstanceOf(OidcServiceProvider::class)
        ->and(config('oidc.http.timeout'))->toBe(0)
        ->and(config('oidc.mfa.max_age'))->toBe('0')
        ->and(config('oidc.post_logout_redirect_uri'))->toBeNull()
        ->and(config('oidc.roles.map'))->toBe(['maintainer' => ['editor', 'viewer']]);
});

it('keeps the published back-channel rate limit, including explicit opt-out', function (?int $rateLimit): void {
    Config::set('oidc.backchannel_logout.rate_limit', $rateLimit);
    app()->register(OidcServiceProvider::class, force: true);

    expect(config('oidc.backchannel_logout.rate_limit'))->toBe($rateLimit);
})->with(['custom rate' => 120, 'off' => null]);

it('keeps null settings that fall back to an optional string default', function (): void {
    Config::set([
        'oidc.break_glass.query_parameter' => null,
        'oidc.roles.claim' => null,
        'oidc.routes.prefix' => null,
        'oidc.users.email_column' => null,
    ]);
    app()->register(OidcServiceProvider::class, force: true);

    expect(config('oidc.break_glass.query_parameter'))->toBeNull()
        ->and(config('oidc.roles.claim'))->toBeNull()
        ->and(config('oidc.routes.prefix'))->toBeNull()
        ->and(config('oidc.users.email_column'))->toBeNull();
});

it('names the key and expected type without printing the invalid value', function (): void {
    Config::set('oidc.backchannel_logout.rate_limit', 'unexpected-rate');

    expect(fn () => app()->register(OidcServiceProvider::class, force: true))
        ->toThrow(InvalidArgumentException::class, 'oidc.backchannel_logout.rate_limit must be a non-negative integer or null.');
});

it('reports the full key when a present config value is invalid at boot', function (string $key, mixed $value): void {
    Config::set($key, $value);

    expect(fn () => app()->register(OidcServiceProvider::class, force: true))
        ->toThrow(InvalidArgumentException::class, $key);
})->with([
    'scalar root' => ['oidc', false],
    'list as root' => ['oidc', ['enabled']],
    'scalar section' => ['oidc.http', 'not-an-array'],
    'list as section' => ['oidc.http', ['connect_timeout']],
    'null section' => ['oidc.cache', null],
    'wrong scalar type' => ['oidc.http.connect_timeout', 'fast'],
    'wrong boolean type' => ['oidc.jit', 'true'],
    'wrong string type' => ['oidc.home', false],
    'explicit null for a required key' => ['oidc.http.connect_timeout', null],
    'negative duration' => ['oidc.id_token.leeway', -1],
    'zero response cap' => ['oidc.http.max_response_bytes', 0],
    'zero maximum retention' => ['oidc.backchannel_logout.max_retention_seconds', 0],
    'invalid optional duration' => ['oidc.mfa.max_age', -1],
    'invalid optional TTL' => ['oidc.backchannel_logout.revocation_ttl', -1],
    'invalid optional string' => ['oidc.issuer', false],
    'invalid cache store type' => ['oidc.cache.store', 42],
    'invalid enum' => ['oidc.token_endpoint_auth_method', 'client_secret_typo'],
    'invalid signing algorithm' => ['oidc.id_token.algorithms', ['HS256']],
    'empty signing algorithms' => ['oidc.id_token.algorithms', []],
    'invalid list member' => ['oidc.scopes', ['openid', 1]],
    'invalid keyed list' => ['oidc.scopes', ['default' => 'openid']],
    'invalid role map' => ['oidc.roles.map', ['maintainer' => [42]]],
    'invalid role map type' => ['oidc.roles.map', 'maintainer'],
    'invalid role map key' => ['oidc.roles.map', ['maintainer']],
]);
