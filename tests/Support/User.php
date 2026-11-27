<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support;

use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * The app user of the test suite, on Testbench's default `users` table.
 * The test schema includes the host application's `is_active` flag.
 */
class User extends Authenticatable
{
    protected $guarded = ['id'];

    protected $hidden = ['password', 'remember_token'];
}
