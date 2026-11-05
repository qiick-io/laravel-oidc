<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use LogicException;
use Qiick\Oidc\Contracts\RoleSynchronizationContract;
use Throwable;

/**
 * Role synchronization for models using spatie/laravel-permission's HasRoles.
 * The package does not depend on Spatie; it calls the trait's methods.
 *
 * A mapped role that does not exist in the app is skipped with a warning
 * instead of failing the login: a typo in the map must not lock users out.
 */
final readonly class SpatieRoleSynchronizationService implements RoleSynchronizationContract
{
    public function synchronize(Model&Authenticatable $user, array $grantedRoles, array $managedRoles): void
    {
        if (! method_exists($user, 'hasRole') || ! method_exists($user, 'assignRole') || ! method_exists($user, 'removeRole')) {
            throw new LogicException('Role mapping needs the Spatie HasRoles trait on the user model, or an app RoleSynchronizationContract.');
        }

        foreach ($managedRoles as $role) {
            $shouldHaveRole = in_array($role, $grantedRoles, true);

            if ($shouldHaveRole === (bool) $user->hasRole($role)) {
                continue;
            }

            try {
                $shouldHaveRole ? $user->assignRole($role) : $user->removeRole($role);
            } catch (Throwable $exception) {
                logger()->warning("OIDC role mapping skipped the role [{$role}]: ".$exception->getMessage());
            }
        }
    }
}
