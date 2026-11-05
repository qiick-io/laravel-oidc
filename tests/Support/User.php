<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support;

use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * The app user of the test suite, on Testbench's default `users` table.
 * `is_active` is added by the tests that need it.
 */
class User extends Authenticatable
{
    protected $guarded = ['id'];

    protected $hidden = ['password', 'remember_token'];
}
