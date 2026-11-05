<?php

declare(strict_types=1);

namespace Qiick\Oidc\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Qiick\Oidc\Data\AuthenticatedIdentityData;

/**
 * A user signed in through SSO; the session is regenerated and holds the
 * identity. Role mapping and activity logs listen here.
 */
final readonly class OidcLoginSucceededEvent
{
    public function __construct(
        public Model&Authenticatable $user,
        public AuthenticatedIdentityData $identity,
    ) {}
}
