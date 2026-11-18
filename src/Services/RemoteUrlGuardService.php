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
 * Ported from Externa's SafeRemoteUrlValidator (the OIDC subset), so the
 * behaviour the apps rely on today stays the same:
 * - only https, or http when private hosts are explicitly allowed (local QA);
 * - no credentials in the URL;
 * - no loopback, private, link-local, CGNAT or reserved addresses, checked on
 *   the literal host and on every address it resolves to;
 * - cloud metadata hosts are blocked even when private hosts are allowed.
 *
 * Server URLs return the resolved addresses, so the HTTP call can pin them and
 * a DNS rebind between check and request cannot reach another host.
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
     * @param  Closure(string): list<string>  $hostResolver  returns the IPv4 and IPv6 addresses of a host name
     */
    public function __construct(
        private bool $isPrivateHostAllowed,
        private Closure $hostResolver,
    ) {}

    /**
     * Checks a URL the server will call (discovery, JWKS, token, userinfo).
     *
     * @return list<string> the addresses to pin the request to; empty when
     *                      private hosts are allowed and resolution failed
     *
     * @throws IdentityProviderRequestException when the URL is not allowed
     */
    public function assertServerUrlIsSafe(string $url): array
    {
        $host = $this->assertSchemeAndExtractHost($url);

        if (! $this->isPrivateHostAllowed && $this->isBlockedHostName($host)) {
            throw $this->blocked($host);
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            if (! $this->isPrivateHostAllowed && $this->isBlockedAddress($host)) {
                throw $this->blocked($host);
            }

            return [$host];
        }

        $resolvedAddresses = ($this->hostResolver)($host);

        if ($this->isPrivateHostAllowed) {
            return $resolvedAddresses;
        }

        if ($resolvedAddresses === []) {
            throw new IdentityProviderRequestException("OIDC endpoint host [{$host}] does not resolve.");
        }

        foreach ($resolvedAddresses as $resolvedAddress) {
            if ($this->isBlockedAddress($resolvedAddress)) {
                throw $this->blocked($host);
            }
        }

        return $resolvedAddresses;
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
        $this->assertSchemeAndExtractHost($url);
    }

    /**
     * Default host resolver: system DNS, A and AAAA records.
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

        return array_values(array_unique($addresses));
    }

    /**
     * @throws IdentityProviderRequestException
     */
    private function assertSchemeAndExtractHost(string $url): string
    {
        $urlParts = parse_url($url);

        if ($urlParts === false || ! isset($urlParts['scheme'], $urlParts['host'])) {
            throw new IdentityProviderRequestException('OIDC endpoint is not an absolute URL.');
        }

        $scheme = strtolower($urlParts['scheme']);
        $isSchemeAllowed = $scheme === 'https' || ($scheme === 'http' && $this->isPrivateHostAllowed);

        if (! $isSchemeAllowed) {
            throw new IdentityProviderRequestException('OIDC endpoints must use https.');
        }

        if (isset($urlParts['user']) || isset($urlParts['pass'])) {
            throw new IdentityProviderRequestException('OIDC endpoints must not contain credentials.');
        }

        $host = trim(strtolower($urlParts['host']), '[]');

        if ($host === '' || in_array($host, self::METADATA_HOSTS, true)) {
            throw $this->blocked($host);
        }

        return $host;
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
        if (filter_var($address, FILTER_VALIDATE_IP) === false) {
            return true;
        }

        if (IpUtils::checkIp($address, self::BLOCKED_NETWORKS)) {
            return true;
        }

        return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    private function blocked(string $host): IdentityProviderRequestException
    {
        return new IdentityProviderRequestException(
            "OIDC endpoint host [{$host}] is not allowed (private, loopback or metadata address). "
            .'Set OIDC_ALLOW_PRIVATE_HOSTS=true only for an IdP on a private network.'
        );
    }
}
