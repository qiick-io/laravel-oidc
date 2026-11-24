<?php

declare(strict_types=1);

use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Services\IdentityProviderHttpService;
use Qiick\Oidc\Services\JwtValidatorService;
use Qiick\Oidc\Services\RoleMappingService;
use Qiick\Oidc\Services\SessionRevocationService;

it('merges the package defaults into the oidc config', function (): void {
    expect(config('oidc'))->toMatchArray([
        'enabled' => false,
        'issuer' => null,
        'client_id' => null,
        'client_secret' => null,
        'button_label' => null,
        'jit' => false,
        'auto_link' => false,
        'only' => false,
    ]);
});

it('lets an app publish the config file', function (): void {
    $this->artisan('vendor:publish', ['--tag' => 'oidc-config', '--force' => true])
        ->assertSuccessful();

    expect(config_path('oidc.php'))->toBeFile();

    unlink(config_path('oidc.php'));
});

/**
 * Reads a private constructor property of a service the container built, to
 * check how the provider translated config into constructor arguments.
 */
function builtWith(string $serviceClass, string $property): mixed
{
    return (fn (): mixed => $this->{$property})->call(app($serviceClass));
}

it('wires the IdP HTTP limits from config and keeps the response cap at one byte or more', function (): void {
    config()->set('oidc.http.timeout', 7);
    config()->set('oidc.http.connect_timeout', 3);
    config()->set('oidc.http.max_response_bytes', 0);

    expect(builtWith(IdentityProviderHttpService::class, 'timeoutSeconds'))->toBe(7)
        ->and(builtWith(IdentityProviderHttpService::class, 'connectTimeoutSeconds'))->toBe(3)
        ->and(builtWith(IdentityProviderHttpService::class, 'maxResponseBytes'))->toBe(1);

    config()->set('oidc.http.max_response_bytes', 2_000_000);

    expect(builtWith(IdentityProviderHttpService::class, 'maxResponseBytes'))->toBe(2_000_000);
});

it('wires the cache lifetimes and the clock leeway from config', function (): void {
    config()->set('oidc.cache.discovery_ttl', 11);
    config()->set('oidc.id_token.leeway', 5);

    expect(builtWith(DiscoveryService::class, 'cacheSeconds'))->toBe(11)
        ->and(builtWith(JwtValidatorService::class, 'leewaySeconds'))->toBe(5);
});

it('keeps only the string entries of the configured lists, as lists', function (): void {
    config()->set('oidc.id_token.algorithms', ['RS256', 5, 'ES256']);

    expect(builtWith(JwtValidatorService::class, 'allowedAlgorithms'))->toBe(['RS256', 'ES256']);
});

it('normalises the role map to string IdP roles with a list of string app roles', function (): void {
    config()->set('oidc.roles.map', [
        'owner' => 'admin',
        'member' => ['editor', 7, 'viewer'],
        'nobody' => [],
        'numbers' => [1, 2],
        3 => 'admin',
    ]);

    expect(builtWith(RoleMappingService::class, 'roleMap'))->toBe([
        'owner' => ['admin'],
        'member' => ['editor', 'viewer'],
    ]);
});

it('keeps revocations for the longer of the configured lifetime and the session lifetime', function (): void {
    config()->set('session.lifetime', 2);
    config()->set('oidc.backchannel_logout.revocation_ttl', 600);

    expect(builtWith(SessionRevocationService::class, 'revocationSeconds'))->toBe(600);

    config()->set('oidc.backchannel_logout.revocation_ttl', 60);

    expect(builtWith(SessionRevocationService::class, 'revocationSeconds'))->toBe(120);
});
