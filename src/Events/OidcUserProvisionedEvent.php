<?php

declare(strict_types=1);

namespace Qiick\Oidc\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Qiick\Oidc\Data\AuthenticatedIdentityData;

/**
 * A local user was created on the first SSO login (JIT provisioning).
 */
final readonly class OidcUserProvisionedEvent
{
    public function __construct(
        public Model&Authenticatable $user,
        public AuthenticatedIdentityData $identity,
    ) {}
}
