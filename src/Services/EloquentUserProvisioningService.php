<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Qiick\Oidc\Contracts\UserProvisioningContract;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Models\UserIdentity;

/**
 * Default JIT provisioning for Laravel's standard `users` table. The password
 * is a random hash nobody knows, so the user can only sign in through SSO
 * until they reset it.
 */
final readonly class EloquentUserProvisioningService implements UserProvisioningContract
{
    public function provision(AuthenticatedIdentityData $identity, string $email): Model&Authenticatable
    {
        $modelClass = UserIdentity::userModel();
        $name = $identity->claim('name');

        /** @var Model&Authenticatable $user */
        $user = new $modelClass;
        $user->forceFill([
            'name' => is_string($name) && trim($name) !== '' ? trim($name) : Str::before($email, '@'),
            'email' => $email,
            'password' => Hash::make(Str::random(64)),
            'email_verified_at' => Date::now(),
        ])->save();

        return $user;
    }
}
