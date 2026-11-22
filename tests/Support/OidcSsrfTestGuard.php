<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support;

use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Outbound\Contracts\HostResolver;
use Qiick\Outbound\Http\PinnedHttpClient;
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
     * Rebind the container guard / pinned client after flipping oidc.http.* config.
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

        app()->instance(HostResolver::class, $resolver);
        app()->instance(UrlGuardOptions::class, new UrlGuardOptions(
            httpsOnly: ! $isPrivateHostAllowed,
            allowPrivateHosts: $isPrivateHostAllowed,
        ));
        app()->forgetInstance(RemoteUrlGuard::class);
        app()->instance(RemoteUrlGuard::class, new RemoteUrlGuard($resolver, allowPrivateHosts: false, httpsOnly: false));
        app()->forgetInstance(PinnedHttpClient::class);
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
                $this->messageForUnsafeUrl($exception, (string) parse_url($url, PHP_URL_HOST)),
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
            $reason = $exception->reason();

            if (str_contains($reason, 'credentials')) {
                throw new IdentityProviderRequestException('OIDC endpoints must not contain credentials.', previous: $exception);
            }

            throw new IdentityProviderRequestException('OIDC endpoints must use https.', previous: $exception);
        }
    }

    private function messageForUnsafeUrl(UnsafeUrl $exception, string $host): string
    {
        $reason = $exception->reason();

        return match (true) {
            str_contains($reason, 'https') && str_contains($reason, 'allowed') => 'OIDC endpoints must use https.',
            str_contains($reason, 'credentials') => 'OIDC endpoints must not contain credentials.',
            str_contains($reason, 'absolute') => 'OIDC endpoint is not an absolute URL.',
            str_contains($reason, 'could not be resolved') => "OIDC endpoint host [{$host}] does not resolve.",
            str_contains($reason, 'disallowed address') => "OIDC endpoint host [{$host}] resolves to a disallowed address. "
                .'Set OIDC_ALLOW_PRIVATE_HOSTS=true only for an IdP on a private network.',
            str_contains($reason, 'invalid') => "OIDC endpoint host [{$host}] is invalid.",
            default => "OIDC endpoint host [{$host}] is not allowed.",
        };
    }
}
