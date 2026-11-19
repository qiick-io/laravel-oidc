<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Closure;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * SSRF guard for every URL the package takes from configuration or from a
 * discovery document. The issuer is admin input and the discovery document is
 * remote input, so neither may point the server at internal services.
 *
 * Behaviour the apps rely on:
 * - only https, or http when private hosts are explicitly allowed (local QA);
 * - no credentials in the URL;
 * - no loopback, private, link-local, CGNAT or reserved addresses, checked on
 *   the literal host and on every address it resolves to;
 * - cloud metadata hosts are blocked even when private hosts are allowed.
 *
 * Every authorised destination is pinned (signaculum-core#189): the guard
 * decides which address the request goes to, and `IdentityProviderHttpService`
 * hands curl exactly that address through CURLOPT_CONNECT_TO with an empty
 * source host. A hostname is resolved once, for A and AAAA; every answer is
 * checked and one of them is returned to pin, so a DNS rebinding answer after
 * the check is never used. A host that resolves to nothing is refused, because
 * there is nothing checked to pin. An IP literal is pinned to itself.
 * CURLOPT_RESOLVE cannot do this job: it is a DNS-cache entry keyed by host
 * name, and curl never consults it for a host it parses as an address itself,
 * such as `2852039166` or `169.254.169.254.`.
 *
 * An IPv4 address written any other way than dotted decimal (`2852039166`,
 * `0251.0376.0251.0376`, `169.254.43518`, a trailing dot) is read the way curl
 * and inet_aton(3) read it, checked against the metadata list, and then
 * refused: an OIDC endpoint has no reason to spell an address like that, and
 * two parsers can disagree on it.
 *
 * An IPv6 literal arrives from `parse_url()` in URL bracket form and is
 * unwrapped and canonicalised before any check. A bracketed host that is not
 * a valid IPv6 literal is refused outright rather than handed to the resolver.
 */
final readonly class RemoteUrlGuardService
{
    /**
     * Beyond FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE: CGNAT,
     * documentation ranges, IPv6 unique-local and link-local.
     */
    private const array BLOCKED_NETWORKS = [
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',
        '240.0.0.0/4',
        '::/128',
        '::1/128',
        'fc00::/7',
        'fe80::/10',
        'ff00::/8',
        '2001:db8::/32',
    ];

    /**
     * Always blocked, also with `allow_private_hosts`.
     */
    private const array METADATA_HOSTS = [
        'metadata',
        'metadata.google.internal',
        '169.254.169.254',
        'fd00:ec2::254',
    ];

    /**
     * @param  Closure(string): list<mixed>  $hostResolver  returns the IPv4 and IPv6 addresses of a host name
     */
    public function __construct(
        private bool $isPrivateHostAllowed,
        private Closure $hostResolver,
    ) {}

    /**
     * Checks a URL the server will call (discovery, JWKS, token, userinfo,
     * end-session, back-channel). Returns exactly one address to pin with
     * CURLOPT_CONNECT_TO; never an empty list.
     *
     * @return list{string} the single address to pin the request to
     *
     * @throws IdentityProviderRequestException when the URL is not allowed
     */
    public function assertServerUrlIsSafe(string $url): array
    {
        $urlParts = $this->parseAbsoluteUrl($url);
        $scheme = strtolower($urlParts['scheme']);
        $isSchemeAllowed = $scheme === 'https' || ($scheme === 'http' && $this->isPrivateHostAllowed);

        if (! $isSchemeAllowed) {
            throw new IdentityProviderRequestException('OIDC endpoints must use https.');
        }

        if (isset($urlParts['user']) || isset($urlParts['pass'])) {
            throw new IdentityProviderRequestException('OIDC endpoints must not contain credentials.');
        }

        $host = strtolower($urlParts['host']);

        // `parse_url()` hands back an IPv6 host with its brackets on; they are URL syntax,
        // not part of the address, and every check below wants the address.
        if (str_contains($host, '[') || str_contains($host, ']')) {
            $literal = $this->unwrapIpv6Literal($host);

            // Brackets mean IPv6 and nothing else (RFC 3986 §3.2.2). Anything else in them
            // is refused here; letting it fall through to the resolver as a name is how a
            // zone id such as `[fe80::1%25en0]` reached curl unchecked.
            if ($literal === null) {
                throw $this->invalidUrl();
            }

            $host = $literal;
        } else {
            // A trailing dot is the DNS root (RFC 1034 §3.1): `localhost.` is `localhost`, and
            // `169.254.169.254.` is the metadata address to curl. The names are compared without it.
            $name = str_ends_with($host, '.') ? substr($host, 0, -1) : $host;

            if ($name === '') {
                throw $this->invalidUrl();
            }

            $ipv4 = $this->readIpv4Address($name);

            if ($ipv4 !== null) {
                if ($this->isMetadataHost($ipv4)) {
                    throw $this->blocked($ipv4);
                }

                // Non-dotted-decimal spellings (and a trailing-dot host) are refused: an OIDC
                // endpoint has no reason to write one, and two parsers can disagree on it
                // (`010.0.0.1` is 8.0.0.1 to curl). Compared to `$host` still carrying a trailing
                // dot when present, so `93.184.216.34.` is invalid here too.
                if ($ipv4 !== $host) {
                    throw $this->invalidUrl();
                }
            }

            $host = $name;
        }

        if ($this->isMetadataHost($host)) {
            throw $this->blocked($host);
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            if (! $this->isPrivateHostAllowed && $this->isBlockedAddress($host)) {
                throw $this->blocked($host);
            }

            return [$host];
        }

        if (! $this->isPrivateHostAllowed && $this->isBlockedHostName($host)) {
            throw $this->blocked($host);
        }

        $resolvedAddresses = $this->resolveHostAddresses($host);

        // Nothing resolved means nothing checked, and so nothing to pin; letting curl resolve
        // the name itself is how every alternate IPv4 spelling reached the metadata service.
        if ($resolvedAddresses === []) {
            throw new IdentityProviderRequestException("OIDC endpoint host [{$host}] does not resolve.");
        }

        foreach ($resolvedAddresses as $resolvedAddress) {
            // The metadata service stays blocked when a name resolves to it, not only when it is
            // named, or the invariant in the class docblock is one DNS record away from false.
            if ($this->isMetadataHost($resolvedAddress) || (! $this->isPrivateHostAllowed && $this->isBlockedAddress($resolvedAddress))) {
                throw new IdentityProviderRequestException(
                    "OIDC endpoint host [{$host}] resolves to a disallowed address. "
                    .'Set OIDC_ALLOW_PRIVATE_HOSTS=true only for an IdP on a private network.'
                );
            }
        }

        return [$this->preferredPinnedAddress($resolvedAddresses)];
    }

    /**
     * Checks a URL the browser is sent to (authorization, end session). The
     * server never calls it, so only the scheme and credentials matter: this
     * stops a hostile discovery document from redirecting to `javascript:` or
     * to a plain-http page.
     *
     * @throws IdentityProviderRequestException when the URL is not allowed
     */
    public function assertBrowserUrlIsSafe(string $url): void
    {
        $urlParts = $this->parseAbsoluteUrl($url);
        $scheme = strtolower($urlParts['scheme']);
        $isSchemeAllowed = $scheme === 'https' || ($scheme === 'http' && $this->isPrivateHostAllowed);

        if (! $isSchemeAllowed) {
            throw new IdentityProviderRequestException('OIDC endpoints must use https.');
        }

        if (isset($urlParts['user']) || isset($urlParts['pass'])) {
            throw new IdentityProviderRequestException('OIDC endpoints must not contain credentials.');
        }
    }

    /**
     * Default host resolver: system DNS, A and AAAA records, then the system
     * resolver (hosts file) when DNS has no answer.
     *
     * @return list<string>
     */
    public static function resolveWithSystemDns(string $host): array
    {
        $addresses = [];
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);

        foreach (is_array($records) ? $records : [] as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;

            if (is_string($address)) {
                $addresses[] = $address;
            }
        }

        if ($addresses === []) {
            $fallbackAddresses = @gethostbynamel($host);
            $addresses = is_array($fallbackAddresses) ? $fallbackAddresses : [];
        }

        return self::canonicalAddresses($addresses);
    }

    /**
     * @return array{scheme: string, host: string, user?: string, pass?: string, port?: int, path?: string, query?: string, fragment?: string}
     *
     * @throws IdentityProviderRequestException
     */
    private function parseAbsoluteUrl(string $url): array
    {
        $urlParts = parse_url($url);

        if ($urlParts === false || ! isset($urlParts['scheme'], $urlParts['host'])) {
            throw new IdentityProviderRequestException('OIDC endpoint is not an absolute URL.');
        }

        /** @var array{scheme: string, host: string, user?: string, pass?: string, port?: int, path?: string, query?: string, fragment?: string} $urlParts */
        return $urlParts;
    }

    private function isMetadataHost(string $host): bool
    {
        foreach ($this->addressForms($host) as $form) {
            if (in_array($form, self::METADATA_HOSTS, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The dotted-decimal address of a host that curl and inet_aton(3) read as IPv4, or null for
     * a host they read as a name.
     *
     * Up to four parts, each decimal, octal (leading `0`) or hexadecimal (`0x`); the last part
     * fills every byte the earlier ones did not, so `169.254.43518` and `2852039166` are both
     * 169.254.169.254. Anything else (five parts, a part out of range, an empty part, a letter
     * outside a `0x` prefix) is a name to both of them, and so to the guard.
     */
    private function readIpv4Address(string $host): ?string
    {
        if (preg_match('/^[0-9a-fx.]+$/', $host) !== 1) {
            return null;
        }

        $parts = explode('.', $host);

        if (count($parts) > 4) {
            return null;
        }

        $numbers = [];

        foreach ($parts as $part) {
            $number = $this->readIpv4Number($part);

            if ($number === null) {
                return null;
            }

            $numbers[] = $number;
        }

        $last = (int) array_pop($numbers);
        $value = 0;

        foreach ($numbers as $number) {
            if ($number > 255) {
                return null;
            }

            $value = $value * 256 + $number;
        }

        $remainingBytes = 4 - count($numbers);

        if ($last >= 256 ** $remainingBytes) {
            return null;
        }

        // Built by hand: long2ip() is string|false on PHP 8.3 stubs and string on 8.4+,
        // and PHPStan at level max rejects either a false-check or an unchecked return.
        $ipLong = $value * 256 ** $remainingBytes + $last;

        return sprintf(
            '%d.%d.%d.%d',
            ($ipLong >> 24) & 0xFF,
            ($ipLong >> 16) & 0xFF,
            ($ipLong >> 8) & 0xFF,
            $ipLong & 0xFF,
        );
    }

    private function readIpv4Number(string $part): ?int
    {
        [$digits, $base] = match (true) {
            preg_match('/^0x[0-9a-f]+$/', $part) === 1 => [substr($part, 2), 16],
            preg_match('/^0[0-7]*$/', $part) === 1 => [$part, 8],
            preg_match('/^[1-9][0-9]*$/', $part) === 1 => [$part, 10],
            default => [null, 0],
        };

        if ($digits === null) {
            return null;
        }

        $digits = ltrim($digits, '0');

        // Eleven digits in any of the three bases already exceed 32 bits, without overflowing.
        if (strlen($digits) > 11) {
            return null;
        }

        $number = $digits === '' ? 0 : intval($digits, $base);

        return $number > 0xFFFFFFFF ? null : $number;
    }

    /**
     * The address inside a URL's IPv6 brackets, canonicalised, or null when the bracketed
     * host is not a valid IPv6 literal.
     *
     * Canonicalising matters as much as unwrapping: METADATA_HOSTS and the blocklist are
     * compared as text, so `[FD00:EC2:0:0:0:0:0:254]` would miss the metadata entry that
     * `[fd00:ec2::254]` hits. `filter_var()` rejects a zone id, an IPv4 address and a
     * hostname in brackets, all of which therefore return null.
     */
    private function unwrapIpv6Literal(string $host): ?string
    {
        if (! str_starts_with($host, '[') || ! str_ends_with($host, ']')) {
            return null;
        }

        $literal = substr($host, 1, -1);

        if (filter_var($literal, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return null;
        }

        $packed = inet_pton($literal);

        return $packed === false ? $literal : (string) inet_ntop($packed);
    }

    /**
     * Every address a host denotes: itself, plus the IPv4 address an IPv6 literal carries.
     *
     * `::ffff:169.254.169.254` (IPv4-mapped, RFC 4291 §2.5.5.2) and `::169.254.169.254`
     * (IPv4-compatible, §2.5.5.1) reach the same host as the IPv4 address inside them, and
     * neither spelling matches an IPv4 entry as text. IpUtils unwraps the mapped form against
     * an IPv4 subnet but not the compatible one, and neither form can match METADATA_HOSTS,
     * so both are expanded here instead.
     *
     * @return list<string>
     */
    private function addressForms(string $address): array
    {
        $packed = @inet_pton($address);

        if ($packed === false || strlen($packed) !== 16) {
            return [$address];
        }

        $prefix = substr($packed, 0, 12);

        if ($prefix !== str_repeat("\0", 10)."\xff\xff" && $prefix !== str_repeat("\0", 12)) {
            return [$address];
        }

        $embedded = inet_ntop(substr($packed, 12));

        return $embedded === false ? [$address] : [$address, $embedded];
    }

    /**
     * The canonical IP addresses a hostname resolves to; anything else a resolver returns is
     * dropped, because only an address may become the pin.
     *
     * @return list<string>
     */
    private function resolveHostAddresses(string $host): array
    {
        return self::canonicalAddresses(($this->hostResolver)($host));
    }

    /**
     * @param  list<mixed>  $addresses
     * @return list<string>
     */
    private static function canonicalAddresses(array $addresses): array
    {
        $canonical = [];

        foreach ($addresses as $address) {
            $packed = is_string($address) ? @inet_pton($address) : false;

            if ($packed !== false) {
                $canonical[] = (string) inet_ntop($packed);
            }
        }

        return array_values(array_unique($canonical));
    }

    /**
     * Prefer an IPv4 pin when both families were validated (curl + Http client quirks).
     *
     * @param  non-empty-list<string>  $addresses
     */
    private function preferredPinnedAddress(array $addresses): string
    {
        foreach ($addresses as $address) {
            if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                return $address;
            }
        }

        return $addresses[0];
    }

    private function isBlockedHostName(string $host): bool
    {
        return in_array($host, ['localhost', 'localhost.localdomain'], true)
            || str_ends_with($host, '.localhost')
            || str_ends_with($host, '.local')
            || str_ends_with($host, '.internal');
    }

    private function isBlockedAddress(string $address): bool
    {
        foreach ($this->addressForms($address) as $form) {
            if (IpUtils::checkIp($form, self::BLOCKED_NETWORKS)) {
                return true;
            }
        }

        return false;
    }

    private function blocked(string $host): IdentityProviderRequestException
    {
        return new IdentityProviderRequestException(
            "OIDC endpoint host [{$host}] is not allowed (private, loopback or metadata address). "
            .'Set OIDC_ALLOW_PRIVATE_HOSTS=true only for an IdP on a private network.'
        );
    }

    private function invalidUrl(): IdentityProviderRequestException
    {
        return new IdentityProviderRequestException('OIDC endpoint URL is invalid.');
    }
}
