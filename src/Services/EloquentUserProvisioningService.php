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
 * Default JIT provisioning for Laravel's standard `users` table. The name is
 * the `name` claim, else `given_name` + `family_name`, else the email's local
 * part. The password is a random hash nobody knows, so the user can only sign
 * in through SSO until they reset it.
 *
 * Apps with first_name / last_name columns bind their own provisioning and
 * use AuthenticatedIdentityData::personName().
 */
final readonly class EloquentUserProvisioningService implements UserProvisioningContract
{
    public function provision(AuthenticatedIdentityData $identity, string $email): Model&Authenticatable
    {
        $modelClass = UserIdentity::userModel();
        $name = $identity->claim('name');
        $fullName = is_string($name) && trim($name) !== '' ? trim($name) : $identity->personName()?->fullName();

        /** @var Model&Authenticatable $user */
        $user = new $modelClass;
        $user->forceFill([
            // A PersonNameData full name is never empty, so null means no name claims at all.
            'name' => $fullName ?? Str::before($email, '@'),
            'email' => $email,
            // Unusable: SSO users sign in through the IdP, never with this password.
            'password' => Hash::make(Str::password()),
            'email_verified_at' => Date::now(),
        ])->save();

        return $user;
    }
}
