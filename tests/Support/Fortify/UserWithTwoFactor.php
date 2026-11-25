<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support\Fortify;

use Qiick\Oidc\Tests\Support\User;

/**
 * A user model with Fortify's two-factor columns, for the default challenge.
 */
class UserWithTwoFactor extends User
{
    use FakeTwoFactorAuthenticatable;

    protected $table = 'users';
}
