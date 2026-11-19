<?php

declare(strict_types=1);

use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Services\RemoteUrlGuardService;

/**
 * @param  list<string>  $resolvedAddresses
 */
function remoteUrlGuard(bool $isPrivateHostAllowed = false, array $resolvedAddresses = ['93.184.215.14']): RemoteUrlGuardService
{
    return new RemoteUrlGuardService($isPrivateHostAllowed, fn (string $host): array => $resolvedAddresses);
}

it('allows a public https endpoint and returns the addresses to pin', function (): void {
    expect(remoteUrlGuard()->assertServerUrlIsSafe('https://idp.example.com/token'))->toBe(['93.184.215.14']);
});

it('refuses unsafe server urls', function (string $url): void {
    remoteUrlGuard()->assertServerUrlIsSafe($url);
})->throws(IdentityProviderRequestException::class)->with([
    'plain http' => 'http://idp.example.com/token',
    'not a url' => 'idp.example.com/token',
    'javascript' => 'javascript:alert(1)',
    'credentials' => 'https://user:secret@idp.example.com/token',
    'localhost' => 'https://localhost/token',
    'dot local' => 'https://idp.local/token',
    'dot internal' => 'https://idp.internal/token',
    'loopback ip' => 'https://127.0.0.1/token',
    'private ip' => 'https://10.1.2.3/token',
    'cgnat ip' => 'https://100.100.100.200/token',
    'ipv6 loopback' => 'https://[::1]/token',
    'ipv6 unique local' => 'https://[fd12::1]/token',
    'metadata ip' => 'https://169.254.169.254/latest',
    'metadata host' => 'https://metadata.google.internal/computeMetadata',
]);

it('refuses a public host name that resolves to a private address', function (): void {
    remoteUrlGuard(resolvedAddresses: ['93.184.215.14', '192.168.1.10'])->assertServerUrlIsSafe('https://idp.example.com/token');
})->throws(IdentityProviderRequestException::class, 'disallowed');

it('refuses a host name that does not resolve, even when private hosts are allowed', function (bool $isPrivateHostAllowed): void {
    remoteUrlGuard($isPrivateHostAllowed, [])->assertServerUrlIsSafe('https://idp.example.com/token');
})->throws(IdentityProviderRequestException::class, 'does not resolve')->with([
    'setting off' => false,
    'setting on' => true,
]);

it('allows private hosts and plain http only when opted in', function (): void {
    $guard = remoteUrlGuard(isPrivateHostAllowed: true, resolvedAddresses: ['172.18.0.5']);

    expect($guard->assertServerUrlIsSafe('http://keycloak:8080/realms/externa/token'))->toBe(['172.18.0.5'])
        ->and($guard->assertServerUrlIsSafe('http://127.0.0.1:8080/token'))->toBe(['127.0.0.1']);
});

it('keeps cloud metadata blocked when private hosts are allowed', function (): void {
    remoteUrlGuard(isPrivateHostAllowed: true)->assertServerUrlIsSafe('http://169.254.169.254/latest/meta-data');
})->throws(IdentityProviderRequestException::class);

it('pins a public ipv4 literal to itself without resolving it', function (): void {
    $guard = new RemoteUrlGuardService(
        false,
        static function (string $host): array {
            throw new RuntimeException("Guard resolved a literal as a name: {$host}");
        },
    );

    expect($guard->assertServerUrlIsSafe('https://93.184.216.34/token'))->toBe(['93.184.216.34']);
});

it('checks only scheme and credentials for browser urls', function (): void {
    remoteUrlGuard(resolvedAddresses: [])->assertBrowserUrlIsSafe('https://login.example.com/authorize');

    expect(fn () => remoteUrlGuard()->assertBrowserUrlIsSafe('javascript:alert(1)'))
        ->toThrow(IdentityProviderRequestException::class)
        ->and(fn () => remoteUrlGuard()->assertBrowserUrlIsSafe('http://login.example.com/authorize'))
        ->toThrow(IdentityProviderRequestException::class);
});
