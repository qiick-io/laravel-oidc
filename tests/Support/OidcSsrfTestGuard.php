<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support;

use Illuminate\Support\Facades\Config;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Factories\OidcOutboundStackFactory;
use Qiick\Oidc\Services\IdentityProviderHttpService;
use Qiick\Outbound\Contracts\HostResolver;
use Qiick\Outbound\Ssrf\RemoteUrlGuard;
use Qiick\Outbound\Ssrf\UnsafeUrl;
use Qiick\Outbound\Ssrf\UrlGuardOptions;
use RuntimeException;

/**
 * Test-only adapter: exercises qiick/laravel-outbound's guard with the same
 * exception type and wording IdentityProviderHttpService exposes to callers.
 */
final class OidcSsrfTestGuard
{
    /**
     * Rebind OIDC's private HostResolver and flip oidc.http.allow_private_hosts.
     * Does not touch the shared outbound container names.
     *
     * @param  list<string>  $resolvedAddresses
     */
    public static function bindInContainer(bool $isPrivateHostAllowed = false, array $resolvedAddresses = ['93.184.215.14']): void
    {
        $resolver = new class($resolvedAddresses) implements HostResolver
        {
            /**
             * @param  list<string>  $addresses
             */
            public function __construct(private array $addresses) {}

            public function resolve(string $host): array
            {
                return $this->addresses;
            }
        };

        Config::set('oidc.http.allow_private_hosts', $isPrivateHostAllowed);
        app()->instance(OidcOutboundStackFactory::HostResolverBinding, $resolver);
    }

    private RemoteUrlGuard $guard;

    private UrlGuardOptions $options;

    /**
     * @param  list<string>|null  $resolvedAddresses  null means the resolver must never run
     */
    public function __construct(
        bool $isPrivateHostAllowed = false,
        ?array $resolvedAddresses = ['93.184.215.14'],
        ?HostResolver $hostResolver = null,
    ) {
        $resolver = $hostResolver ?? ($resolvedAddresses === null
            ? new class implements HostResolver
            {
                public function resolve(string $host): array
                {
                    throw new RuntimeException("Guard resolved a literal as a name: {$host}");
                }
            }
            : new class($resolvedAddresses) implements HostResolver
            {
                /**
                 * @param  list<string>  $addresses
                 */
                public function __construct(private array $addresses) {}

                public function resolve(string $host): array
                {
                    return $this->addresses;
                }
            });

        $this->guard = new RemoteUrlGuard($resolver, allowPrivateHosts: false, httpsOnly: false);
        $this->options = new UrlGuardOptions(
            httpsOnly: ! $isPrivateHostAllowed,
            allowPrivateHosts: $isPrivateHostAllowed,
        );
    }

    /**
     * @return list{string}
     *
     * @throws IdentityProviderRequestException
     */
    public function assertServerUrlIsSafe(string $url): array
    {
        try {
            $destination = $this->guard->authorize($url, $this->options);
        } catch (UnsafeUrl $exception) {
            throw new IdentityProviderRequestException(
                IdentityProviderHttpService::messageForUnsafeUrl($exception, (string) parse_url($url, PHP_URL_HOST)),
                previous: $exception,
            );
        }

        return [$destination->pinnedAddress];
    }

    /**
     * @throws IdentityProviderRequestException
     */
    public function assertBrowserUrlIsSafe(string $url): void
    {
        try {
            $this->guard->assertBrowserUrlIsSafe($url, $this->options);
        } catch (UnsafeUrl $exception) {
            throw new IdentityProviderRequestException(
                IdentityProviderHttpService::messageForUnsafeUrl($exception, (string) parse_url($url, PHP_URL_HOST)),
                previous: $exception,
            );
        }
    }
}
