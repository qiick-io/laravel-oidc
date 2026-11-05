<?php

declare(strict_types=1);

namespace Qiick\Oidc\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Qiick\Oidc\Data\AuthenticatedIdentityData;

/**
 * An SSO identity was linked to an existing local user by verified email
 * (auto-link). Worth an entry in the app's activity log.
 */
final readonly class OidcIdentityLinkedEvent
{
    public function __construct(
        public Model&Authenticatable $user,
        public AuthenticatedIdentityData $identity,
    ) {}
}
