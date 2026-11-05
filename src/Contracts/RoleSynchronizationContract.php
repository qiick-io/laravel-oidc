<?php

declare(strict_types=1);

namespace Qiick\Oidc\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * Applies the roles computed by the role mapping to a local user. The default
 * works with spatie/laravel-permission (Externa and Excubia App); an app with
 * another role system binds its own.
 */
interface RoleSynchronizationContract
{
    /**
     * Grant every role in $grantedRoles and revoke every other role in
     * $managedRoles. Roles outside $managedRoles must not be touched.
     *
     * @param  list<string>  $grantedRoles  always a subset of $managedRoles
     * @param  list<string>  $managedRoles
     */
    public function synchronize(Model&Authenticatable $user, array $grantedRoles, array $managedRoles): void;
}
