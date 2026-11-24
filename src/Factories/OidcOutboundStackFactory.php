<?php

declare(strict_types=1);

namespace Qiick\Oidc\Factories;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Client\Factory as HttpFactory;
use LogicException;
use Qiick\Oidc\Data\OidcOutboundStackData;
use Qiick\Oidc\Services\IdentityProviderHttpService;
use Qiick\Oidc\Testing\FakeIdentityProvider;
use Qiick\Outbound\Contracts\HostResolver;
use Qiick\Outbound\Http\OutboundHttpLimits;
use Qiick\Outbound\Http\PinnedHttpClient;
use Qiick\Outbound\Laravel\OutboundServiceProvider;
use Qiick\Outbound\Ssrf\RemoteUrlGuard;
use Qiick\Outbound\Ssrf\UrlGuardOptions;

/**
 * Builds the IdP HTTP stack privately so {@see OutboundServiceProvider}
 * cannot override SSRF or timeouts when both packages are installed.
 *
 * Uses the app's shared {@see HttpFactory} so `Http::fake()` and
 * {@see FakeIdentityProvider} still intercept IdP calls. DNS is swapped through
 * {@see HostResolverBinding} only.
 *
 * @internal Not part of the public API (docs/PUBLIC-API.md); it can change in any release.
 */
final readonly class OidcOutboundStackFactory
{
    /**
     * Private HostResolver for IdP SSRF. Never the shared outbound binding.
     */
    public const string HostResolverBinding = 'oidc.ssrf.host_resolver';

    public function __construct(
        private HttpFactory $http,
        private ConfigRepository $config,
        private mixed $hostResolver,
    ) {}

    /**
     * @throws LogicException when the host resolver binding is the wrong type
     */
    public function make(): OidcOutboundStackData
    {
        if (! $this->hostResolver instanceof HostResolver) {
            throw new LogicException('OIDC host resolver binding must resolve to a HostResolver.');
        }

        $isPrivateHostAllowed = $this->config->boolean('oidc.http.allow_private_hosts');
        // Defaults are dead: mergeConfigFrom always publishes oidc.http.timeout / connect_timeout.
        $timeoutSeconds = IdentityProviderHttpService::resolveTimeoutSeconds(
            $this->config->integer('oidc.http.timeout', 10), // @pest-mutate-ignore: IncrementInteger,DecrementInteger
        );
        $connectTimeoutSeconds = IdentityProviderHttpService::resolveTimeoutSeconds(
            $this->config->integer('oidc.http.connect_timeout', 10), // @pest-mutate-ignore: IncrementInteger,DecrementInteger
        );

        $remoteUrlGuard = new RemoteUrlGuard(
            hostResolver: $this->hostResolver,
            allowPrivateHosts: false,
            httpsOnly: false,
        );
        $urlGuardOptions = new UrlGuardOptions(
            httpsOnly: ! $isPrivateHostAllowed,
            allowPrivateHosts: $isPrivateHostAllowed,
        );
        $httpLimits = new OutboundHttpLimits(
            maxTimeoutSeconds: max(60, $timeoutSeconds),
            maxConnectTimeoutSeconds: max(30, $connectTimeoutSeconds),
            totalDeadlineSeconds: max(30, $timeoutSeconds * 3),
        );
        $pinnedHttp = new PinnedHttpClient(
            $this->http,
            $remoteUrlGuard,
            $httpLimits,
        );

        return new OidcOutboundStackData($pinnedHttp, $urlGuardOptions, $remoteUrlGuard, $httpLimits);
    }
}
