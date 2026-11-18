<?php

declare(strict_types=1);

namespace Qiick\Oidc\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Qiick\Oidc\Data\AuthenticatedIdentityData;

/**
 * Creates the local user on a JIT login. Every app has its own user columns
 * and default role (Externa: first and last name plus `default_user_role`;
 * Excubia App: the `reader` role), so apps bind their own implementation.
 * The default fills `name`, `email`, an unusable password and
 * `email_verified_at`.
 *
 * Runs inside the database transaction that also stores the identity.
 */
interface UserProvisioningContract
{
    /**
     * @param  string  $email  the verified, lower-cased email
     */
    public function provision(AuthenticatedIdentityData $identity, string $email): Model&Authenticatable;
}
