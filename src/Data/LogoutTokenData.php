<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

/**
 * A validated back-channel `logout_token`. At least one of `subject` and
 * `sessionId` is set: with `sid` only that IdP session ends, with `sub` alone
 * every session of the user ends.
 */
final readonly class LogoutTokenData
{
    public function __construct(
        public string $issuer,
        public ?string $subject,
        public ?string $sessionId,
    ) {}
}
