<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

/**
 * A validated logout (back-channel token or front-channel query).
 *
 * At least one of `subject` and `sessionId` is set: with `sid` only that IdP
 * session ends, with `sub` alone every session of the user ends. Trailing
 * fields feed the durable `oidc_logout_revocations` row (M10).
 *
 * @internal Not part of the public API (docs/PUBLIC-API.md); it can change in any release.
 */
final readonly class LogoutTokenData
{
    public function __construct(
        public string $issuer,
        public ?string $subject,
        public ?string $sessionId,
        public ?string $tokenId = null,
        public ?int $expiresAt = null,
        public string $channel = 'backchannel',
    ) {}
}
