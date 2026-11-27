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
use Qiick\Outbound\Http\OutboundHttpStackData;
use Qiick\Outbound\Laravel\OutboundServiceProvider;
use Qiick\Outbound\Ssrf\UrlGuardOptions;

/**
 * Builds the IdP HTTP stack privately so {@see OutboundServiceProvider}
 * cannot override SSRF or timeouts when both packages are installed.
 *
 * Uses the app's shared {@see HttpFactory} so `Http::fake()` and
 * {@see FakeIdentityProvider} still intercept IdP calls. DNS is swapped through
 * {@see HostResolverBinding} only.
 *
 * @internal Not part of the public API (docs/public-api.md); it can change in any release.
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
        // The service provider merges the package defaults into nested keys,
        // so both keys exist even in a config published before they did.
        $timeoutSeconds = IdentityProviderHttpService::resolveTimeoutSeconds($this->config->integer('oidc.http.timeout'));
        $connectTimeoutSeconds = IdentityProviderHttpService::resolveTimeoutSeconds($this->config->integer('oidc.http.connect_timeout'));

        $urlGuardOptions = new UrlGuardOptions(
            httpsOnly: ! $isPrivateHostAllowed,
            allowPrivateHosts: $isPrivateHostAllowed,
        );
        $httpLimits = new OutboundHttpLimits(
            maxTimeoutSeconds: max(60, $timeoutSeconds),
            maxConnectTimeoutSeconds: max(30, $connectTimeoutSeconds),
            totalDeadlineSeconds: max(30, $timeoutSeconds * 3),
        );
        $outbound = OutboundHttpStackData::make(
            $this->hostResolver,
            allowPrivateHosts: $isPrivateHostAllowed,
            httpsOnly: false,
            limits: $httpLimits,
            httpFactory: $this->http,
        );

        return new OidcOutboundStackData($outbound->client, $urlGuardOptions, $outbound->guard, $httpLimits);
    }
}
