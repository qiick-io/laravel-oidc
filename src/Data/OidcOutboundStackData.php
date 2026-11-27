<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

use Qiick\Outbound\Http\OutboundHttpLimits;
use Qiick\Outbound\Http\PinnedHttpClient;
use Qiick\Outbound\Ssrf\RemoteUrlGuard;
use Qiick\Outbound\Ssrf\UrlGuardOptions;

/**
 * The OIDC-private outbound stack: never the shared outbound container bindings.
 *
 * @internal Not part of the public API (docs/public-api.md); it can change in any release.
 */
final readonly class OidcOutboundStackData
{
    public function __construct(
        public PinnedHttpClient $pinnedHttp,
        public UrlGuardOptions $urlGuardOptions,
        public RemoteUrlGuard $remoteUrlGuard,
        public OutboundHttpLimits $httpLimits,
    ) {}
}
