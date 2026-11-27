<?php

declare(strict_types=1);

use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Services\IdentityProviderHttpService;
use Qiick\Oidc\Tests\Support\OidcSsrfTestGuard;
use Qiick\Outbound\Contracts\HostResolver;
use Qiick\Outbound\Http\OutboundHttpStackData;
use Qiick\Outbound\Ssrf\UrlGuardOptions;

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
function pinGuard(bool $isPrivateHostAllowed = false, array $resolvedAddresses = ['93.184.216.34']): OidcSsrfTestGuard
{
    return new OidcSsrfTestGuard($isPrivateHostAllowed, $resolvedAddresses);
}

function pinGuardThatMustNotResolve(bool $isPrivateHostAllowed = false): OidcSsrfTestGuard
{
    return new OidcSsrfTestGuard($isPrivateHostAllowed, null);
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

/**
 * Every spelling the guard canonicalises to the Alibaba (100.100.100.200) and
 * Oracle (192.0.0.192) metadata addresses. Both sit in ranges that are blocked
 * while private hosts are off; the regression is that `OIDC_ALLOW_PRIVATE_HOSTS=true`
 * made them reachable, so each case runs with both settings.
 */
dataset('cloud metadata ipv4 spellings', [
    'alibaba dotted decimal' => 'https://100.100.100.200/latest/meta-data/',
    'alibaba dotted decimal with a port' => 'https://100.100.100.200:443/latest/meta-data/',
    'alibaba decimal' => 'https://1684301000/latest/meta-data/',
    'alibaba dotted octal' => 'https://0144.0144.0144.0310/latest/meta-data/',
    'alibaba dotted hex' => 'https://0x64.0x64.0x64.0xc8/latest/meta-data/',
    'alibaba dotted hex, upper case' => 'https://0X64.0X64.0X64.0XC8/latest/meta-data/',
    'alibaba one hex number' => 'https://0x646464c8/latest/meta-data/',
    'alibaba one octal number' => 'https://014431062310/latest/meta-data/',
    'alibaba mixed bases' => 'https://100.0144.0x64.200/latest/meta-data/',
    'alibaba three parts' => 'https://100.100.25800/latest/meta-data/',
    'alibaba two parts' => 'https://100.6579400/latest/meta-data/',
    'alibaba trailing dot' => 'https://100.100.100.200./latest/meta-data/',
    'oracle dotted decimal' => 'https://192.0.0.192/latest/meta-data/',
    'oracle dotted decimal with a port' => 'https://192.0.0.192:443/latest/meta-data/',
    'oracle decimal' => 'https://3221225664/latest/meta-data/',
    'oracle dotted octal' => 'https://0300.0.0.0300/latest/meta-data/',
    'oracle one octal number' => 'https://030000000300/latest/meta-data/',
    'oracle dotted hex' => 'https://0xc0.0x0.0x0.0xc0/latest/meta-data/',
    'oracle dotted hex, upper case' => 'https://0XC0.0X0.0X0.0XC0/latest/meta-data/',
    'oracle one hex number' => 'https://0xc00000c0/latest/meta-data/',
    'oracle mixed bases' => 'https://0300.0x0.0.192/latest/meta-data/',
    'oracle three parts' => 'https://192.0.192/latest/meta-data/',
    'oracle two parts' => 'https://192.192/latest/meta-data/',
    'oracle trailing dot' => 'https://192.0.0.192./latest/meta-data/',
]);

it('refuses every spelling of the ipv4 metadata address, whatever the setting', function (string $url, bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuard($isPrivateHostAllowed)->assertServerUrlIsSafe($url))
        ->toThrow(IdentityProviderRequestException::class, 'not allowed');
})->with('metadata ipv4 spellings')->with('private host setting');

it('reads an ipv4 spelling as the address it is, and never looks it up as a name', function (string $url, bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuardThatMustNotResolve($isPrivateHostAllowed)->assertServerUrlIsSafe($url))
        ->toThrow(IdentityProviderRequestException::class);
})->with('metadata ipv4 spellings')->with('private host setting');

it('refuses every spelling of the alibaba and oracle metadata addresses, whatever the setting', function (string $url, bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuard($isPrivateHostAllowed)->assertServerUrlIsSafe($url))
        ->toThrow(IdentityProviderRequestException::class, 'not allowed');
})->with('cloud metadata ipv4 spellings')->with('private host setting');

it('reads an alibaba or oracle metadata spelling as the address it is, and never looks it up as a name', function (string $url, bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuardThatMustNotResolve($isPrivateHostAllowed)->assertServerUrlIsSafe($url))
        ->toThrow(IdentityProviderRequestException::class);
})->with('cloud metadata ipv4 spellings')->with('private host setting');

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
    'a hostname made of hex letters' => 'https://deadbeef.example.com/token',
]);

// outbound IDN normalisation refuses empty DNS labels; oidc previously resolved
// `1..2` as a name. Stricter is fine (behaviour must not loosen).
it('refuses a hostname with an empty DNS label', function (): void {
    expect(fn () => pinGuard()->assertServerUrlIsSafe('https://1..2/token'))
        ->toThrow(IdentityProviderRequestException::class, 'invalid');
});

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

it('refuses a hostname that resolves to an alibaba or oracle metadata address, whatever the setting', function (array $addresses, bool $isPrivateHostAllowed): void {
    expect(fn () => pinGuard($isPrivateHostAllowed, $addresses)->assertServerUrlIsSafe('https://metadata.attacker.example/latest/meta-data/'))
        ->toThrow(IdentityProviderRequestException::class, 'disallowed');
})->with([
    'alibaba ipv4' => [['100.100.100.200']],
    'alibaba ipv4 mapped' => [['::ffff:100.100.100.200']],
    'alibaba ipv4 mapped in hextets' => [['::ffff:6464:64c8']],
    'alibaba ipv4 compatible' => [['::100.100.100.200']],
    'alibaba ipv4 compatible in hextets' => [['::6464:64c8']],
    'alibaba behind a public answer' => [['93.184.216.34', '100.100.100.200']],
    'oracle ipv4' => [['192.0.0.192']],
    'oracle ipv4 mapped' => [['::ffff:192.0.0.192']],
    'oracle ipv4 mapped in hextets' => [['::ffff:c000:c0']],
    'oracle ipv4 compatible' => [['::192.0.0.192']],
    'oracle ipv4 compatible in hextets' => [['::c000:c0']],
    'oracle behind a public answer' => [['93.184.216.34', '192.0.0.192']],
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

/**
 * @param  callable(string): list<string>  $resolve
 */
function identityProviderHttpWithResolver(callable $resolve): IdentityProviderHttpService
{
    $resolver = new class($resolve) implements HostResolver
    {
        /**
         * @param  callable(string): list<string>  $resolve
         */
        public function __construct(private mixed $resolve) {}

        public function resolve(string $host): array
        {
            return ($this->resolve)($host);
        }
    };

    $options = new UrlGuardOptions(httpsOnly: true, allowPrivateHosts: false);
    $outbound = OutboundHttpStackData::make($resolver, httpsOnly: false, httpFactory: app(HttpFactory::class));

    return new IdentityProviderHttpService($outbound->client, $options, 5);
}

it('resolves once per request and sends it to the address the guard checked', function (): void {
    $lookups = 0;
    $sentOptions = null;

    Http::fake(function (Request $request, array $options) use (&$sentOptions): PromiseInterface {
        $sentOptions = $options;

        return Http::response(['iss' => 'https://rebind.example.com', 'ok' => true], 200);
    });

    $http = identityProviderHttpWithResolver(
        static function (string $_host) use (&$lookups): array {
            $lookups++;

            return $lookups === 1 ? ['93.184.216.34'] : ['169.254.169.254'];
        },
    );

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

    $http = identityProviderHttpWithResolver(
        static function (string $host): array {
            throw new RuntimeException("Guard resolved an address literal as a name: {$host}");
        },
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

    $http = identityProviderHttpWithResolver(
        static function (string $host): array {
            throw new RuntimeException("Guard resolved an address literal as a name: {$host}");
        },
    );

    $http->getJson('https://[2606:2800:220:1:248:1893:25c8:1946]/token');

    expect($sentOptions['curl'] ?? null)->toBe([
        CURLOPT_CONNECT_TO => ['::[2606:2800:220:1:248:1893:25c8:1946]:443'],
    ]);
});
