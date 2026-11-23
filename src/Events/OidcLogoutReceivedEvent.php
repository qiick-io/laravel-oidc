<?php

declare(strict_types=1);

namespace Qiick\Oidc\Events;

/**
 * The IdP logged a user out through back-channel or front-channel logout, and
 * the revocation is stored (standards review S8). Products listen to it to
 * write their activity log without a package table.
 *
 * `channel` is `backchannel` or `frontchannel`. It carries no token: `sessionIdHash` is the SHA-256 of the IdP session id
 * (`sid`), enough to correlate entries without storing the identifier itself.
 */
final readonly class OidcLogoutReceivedEvent
{
    public function __construct(
        public string $channel,
        public string $issuer,
        public ?string $subject,
        public ?string $sessionIdHash,
    ) {}
}
