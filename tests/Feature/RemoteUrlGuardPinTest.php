<?php

declare(strict_types=1);

use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Services\IdentityProviderHttpService;
use Qiick\Oidc\Services\RemoteUrlGuardService;

/**
 * What curl connects to, and how the guard knows it checked that address.
 *
 * Ported from signaculum-core#189 (WebhookUrlGuardPinTest). `filter_var()` rejects
 * `2852039166`, `0251.0376.0251.0376` and `169.254.169.254.`, but curl and inet_aton(3)
 * read each of them as 169.254.169.254. Before the fix the guard treated them as DNS
 * names: with `OIDC_ALLOW_PRIVATE_HOSTS` on they went out unpinned, and with it off they
 * were refused only when the lookup of the string happened to fail. CURLOPT_RESOLVE
 * cannot pin a host curl parses as an address, so the HTTP layer must use
 * CURLOPT_CONNECT_TO with an empty source host.
 *
 * Every resolver below answers with a public address unless a test says otherwise, so a
 * refusal cannot come from a lookup that failed. OIDC endpoints stay https unless private
 * hosts are opted in (lab IdPs).
 *
 * @param  list<string>  $resolvedAddresses
 */
function pinGuard(bool $isPrivateHostAllowed = false, array $resolvedAddresses = ['93.184.216.34']): RemoteUrlGuardService
{
    return new RemoteUrlGuardService($isPrivateHostAllowed, static fn (string $_host): array => $resolvedAddresses);
}

function pinGuardThatMustNotResolve(bool $isPrivateHostAllowed = false): RemoteUrlGuardService
{
    return new RemoteUrlGuardService(
        $isPrivateHostAllowed,
        static function (string $host): array {
            throw new RuntimeException("Guard resolved an address literal as a name: {$host}");
        },
    );
}

dataset('private host setting', [
    'setting off' => false,
    'setting on' => true,
]);

dataset('metadata ipv4 spellings', [
    'decimal' => 'https://2852039166/latest/meta-data/',
    'decimal with a port' => 'https://2852039166:443/latest/meta-data/',
    'dotted octal' => 'https://0251.0376.0251.0376/latest/meta-data/',
    'dotted hex' => 'https://0xa9.0xfe.0xa9.0xfe/latest/meta-data/',
    'dotted hex, upper case' => 'https://0XA9.0XFE.0XA9.0XFE/latest/meta-data/',
    'one hex number' => 'https://0xa9fea9fe/latest/meta-data/',
    'one octal number' => 'https://025177524776/latest/meta-data/',
    'mixed bases' => 'https://169.0376.0xa9.254/latest/meta-data/',
    'three parts' => 'https://169.254.43518/latest/meta-data/',
    'two parts' => 'https://169.16689662/latest/meta-data/',
    'trailing dot' => 'https://169.254.169.254./latest/meta-data/',
    'decimal with a trailing dot' => 'https://2852039166./latest/meta-data/',
]);

it('refuses every spelling of the ipv4 metadata address, whatever the setting', function (string $url, bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuard($isPrivateHostAllowed)->assertServerUrlIsSafe($url))
        ->toThrow(IdentityProviderRequestException::class, 'not allowed');
})->with('metadata ipv4 spellings')->with('private host setting');

it('reads an ipv4 spelling as the address it is, and never looks it up as a name', function (string $url, bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuardThatMustNotResolve($isPrivateHostAllowed)->assertServerUrlIsSafe($url))
        ->toThrow(IdentityProviderRequestException::class);
})->with('metadata ipv4 spellings')->with('private host setting');

it('refuses an ipv4 address that is not written in dotted decimal, whatever the setting', function (string $url, bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuardThatMustNotResolve($isPrivateHostAllowed)->assertServerUrlIsSafe($url))
        ->toThrow(IdentityProviderRequestException::class, 'invalid');
})->with([
    'short form, link local (169.254.255.254)' => 'https://169.254.65534/token',
    'short form, public (1.0.0.1)' => 'https://1.1/token',
    'decimal loopback' => 'https://2130706433/token',
    'hex loopback, two parts' => 'https://0x7f.1/token',
    'short loopback' => 'https://127.1/token',
    'octal private' => 'https://012.0.0.1/token',
    'leading zeroes' => 'https://127.000.000.001/token',
    'decimal public (93.184.216.34)' => 'https://1572395042/token',
    'canonical public with a trailing dot' => 'https://93.184.216.34./token',
])->with('private host setting');

it('still treats a name that only looks numeric as a name', function (string $url): void {
    expect(pinGuard()->assertServerUrlIsSafe($url))->toBe(['93.184.216.34']);
})->with([
    'five parts' => 'https://1.2.3.4.5/token',
    'a part over 255' => 'https://256.1.1.1/token',
    'a whole address over 32 bits' => 'https://4294967296/token',
    'a last part too big for the bytes left' => 'https://1.16777216/token',
    'twelve significant digits' => 'https://123456789012/token',
    'hex digits without the prefix' => 'https://cafe.1.2.3/token',
    'an empty part' => 'https://1..2/token',
    'a hostname made of hex letters' => 'https://deadbeef.example.com/token',
]);

it('refuses a hostname that resolves to the metadata address, whatever the setting', function (array $addresses, bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuard($isPrivateHostAllowed, $addresses)->assertServerUrlIsSafe('https://metadata.attacker.example/latest/meta-data/'))
        ->toThrow(IdentityProviderRequestException::class, 'disallowed');
})->with([
    'ec2 ipv4' => [['169.254.169.254']],
    'ec2 ipv6' => [['fd00:ec2::254']],
    'ec2 ipv6, uncompressed' => [['FD00:EC2:0:0:0:0:0:254']],
    'ipv4 mapped' => [['::ffff:169.254.169.254']],
    'ipv4 compatible' => [['::169.254.169.254']],
    'behind a public answer' => [['93.184.216.34', '169.254.169.254']],
])->with('private host setting');

it('keeps the metadata names blocked with a trailing dot', function (string $url, bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuard($isPrivateHostAllowed)->assertServerUrlIsSafe($url))
        ->toThrow(IdentityProviderRequestException::class, 'not allowed');
})->with([
    'gce metadata name' => 'https://metadata.google.internal./computeMetadata/v1/',
    'bare metadata name' => 'https://metadata./computeMetadata/v1/',
])->with('private host setting');

it('keeps the blocked names blocked with a trailing dot', function (string $url): void {
    expect(fn () => pinGuard()->assertServerUrlIsSafe($url))
        ->toThrow(IdentityProviderRequestException::class, 'not allowed');
})->with([
    'localhost' => 'https://localhost./token',
    'an internal name' => 'https://redis.internal./token',
    'an mdns name' => 'https://printer.local./token',
]);

it('pins every destination it authorises to exactly one checked address', function (string $url, array $addresses, bool $isPrivateHostAllowed, string $pinnedAddress): void {
    expect(pinGuard($isPrivateHostAllowed, $addresses)->assertServerUrlIsSafe($url))->toBe([$pinnedAddress]);
})->with([
    'a public hostname' => ['https://idp.example.com/token', ['93.184.216.34'], false, '93.184.216.34'],
    'a hostname with a port' => ['https://idp.example.com:8443/token', ['93.184.216.34'], false, '93.184.216.34'],
    'a fully qualified hostname' => ['https://idp.example.com./token', ['93.184.216.34'], false, '93.184.216.34'],
    'a hostname with only ipv6' => ['https://v6.example.com/token', ['2606:2800:220:1:248:1893:25c8:1946'], false, '2606:2800:220:1:248:1893:25c8:1946'],
    'a public ipv4 literal' => ['https://93.184.216.34/token', [], false, '93.184.216.34'],
    'a public ipv6 literal' => ['https://[2606:2800:220:1:248:1893:25c8:1946]/token', [], false, '2606:2800:220:1:248:1893:25c8:1946'],
    'a public ipv4 mapped literal' => ['https://[::ffff:93.184.216.34]/token', [], false, '::ffff:93.184.216.34'],
    'a private literal, setting on' => ['http://10.0.0.5:8080/token', [], true, '10.0.0.5'],
    'a private ipv6 literal, setting on' => ['http://[fc00::1]:8443/token', [], true, 'fc00::1'],
    'a hostname answering privately, setting on' => ['http://idp.lan.example/token', ['10.0.0.5'], true, '10.0.0.5'],
    'localhost, setting on' => ['http://localhost:9000/token', ['127.0.0.1'], true, '127.0.0.1'],
]);

it('refuses a host that is nothing but the root dot', function (): void {
    expect(fn () => pinGuardThatMustNotResolve()->assertServerUrlIsSafe('https://./token'))
        ->toThrow(IdentityProviderRequestException::class, 'invalid');
});

it('refuses a host that does not resolve, whatever the setting, because there is nothing to pin', function (bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuard($isPrivateHostAllowed, [])->assertServerUrlIsSafe('https://nxdomain.example.com/token'))
        ->toThrow(IdentityProviderRequestException::class, 'does not resolve');
})->with('private host setting');

it('never pins a resolver answer that is not an address', function (bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuard($isPrivateHostAllowed, ['metadata.google.internal'])->assertServerUrlIsSafe('https://cname.example.com/token'))
        ->toThrow(IdentityProviderRequestException::class, 'does not resolve')
        ->and(pinGuard($isPrivateHostAllowed, ['metadata.google.internal', '93.184.216.34'])->assertServerUrlIsSafe('https://cname.example.com/token'))
        ->toBe(['93.184.216.34']);
})->with('private host setting');

it('checks every record of a hostname, and pins one of them, ipv4 first', function (): void {
    $addresses = ['2606:2800:220:1:248:1893:25c8:1946', '93.184.216.34', '93.184.216.35'];

    expect(pinGuard(resolvedAddresses: $addresses)->assertServerUrlIsSafe('https://many.example.com/token'))
        ->toBe(['93.184.216.34'])
        ->and(fn () => pinGuard(resolvedAddresses: [...$addresses, '10.0.0.5'])->assertServerUrlIsSafe('https://many.example.com/token'))
        ->toThrow(IdentityProviderRequestException::class, 'disallowed');
});

it('resolves once per request and sends it to the address the guard checked', function (): void {
    $lookups = 0;
    $guard = new RemoteUrlGuardService(
        false,
        static function (string $_host) use (&$lookups): array {
            $lookups++;

            return $lookups === 1 ? ['93.184.216.34'] : ['169.254.169.254'];
        },
    );

    $sentOptions = null;

    Http::fake(function (Request $request, array $options) use (&$sentOptions): PromiseInterface {
        $sentOptions = $options;

        return Http::response(['iss' => 'https://rebind.example.com', 'ok' => true], 200);
    });

    $http = new IdentityProviderHttpService(Http::getFacadeRoot(), $guard, 5);

    expect($http->getJson('https://rebind.example.com/token'))->toBe(['iss' => 'https://rebind.example.com', 'ok' => true])
        ->and($lookups)->toBe(1)
        ->and($sentOptions['curl'] ?? null)->toBe([CURLOPT_CONNECT_TO => ['::93.184.216.34:443']]);

    expect(fn () => $http->getJson('https://rebind.example.com/token'))
        ->toThrow(IdentityProviderRequestException::class, 'disallowed');

    expect($lookups)->toBe(2);
    Http::assertSentCount(1);
});

it('pins a literal address in the url with CURLOPT_CONNECT_TO, never CURLOPT_RESOLVE', function (): void {
    $sentOptions = null;

    Http::fake(function (Request $request, array $options) use (&$sentOptions): PromiseInterface {
        $sentOptions = $options;

        return Http::response(['ok' => true], 200);
    });

    $http = new IdentityProviderHttpService(
        Http::getFacadeRoot(),
        pinGuardThatMustNotResolve(),
        5,
    );

    $http->getJson('https://93.184.216.34/token');

    expect($sentOptions['curl'] ?? null)->toBe([CURLOPT_CONNECT_TO => ['::93.184.216.34:443']])
        ->and(array_key_exists(CURLOPT_RESOLVE, $sentOptions['curl'] ?? []))->toBeFalse();
});

it('pins an ipv6 literal with brackets in CURLOPT_CONNECT_TO', function (): void {
    $sentOptions = null;

    Http::fake(function (Request $request, array $options) use (&$sentOptions): PromiseInterface {
        $sentOptions = $options;

        return Http::response(['ok' => true], 200);
    });

    $http = new IdentityProviderHttpService(
        Http::getFacadeRoot(),
        pinGuardThatMustNotResolve(),
        5,
    );

    $http->getJson('https://[2606:2800:220:1:248:1893:25c8:1946]/token');

    expect($sentOptions['curl'] ?? null)->toBe([
        CURLOPT_CONNECT_TO => ['::[2606:2800:220:1:248:1893:25c8:1946]:443'],
    ]);
});
