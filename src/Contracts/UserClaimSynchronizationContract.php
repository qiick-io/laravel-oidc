<?php

declare(strict_types=1);

namespace Qiick\Oidc\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Qiick\Oidc\Data\AuthenticatedIdentityData;

/**
 * Optionally updates the local user from profile claims after every SSO login.
 *
 * Bound to a no-op by default (standards review S9): overwriting admin-edited
 * names or locales is product policy. Products that want live profile sync
 * bind their own implementation.
 */
interface UserClaimSynchronizationContract
{
    /**
     * Apply IdP profile claims to the local user. Must not touch roles
     * (RoleSynchronizationContract) or authentication state.
     */
    public function synchronize(Model&Authenticatable $user, AuthenticatedIdentityData $identity): void;
}
