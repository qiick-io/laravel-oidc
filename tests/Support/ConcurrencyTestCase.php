<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Orchestra\Testbench\Attributes\WithMigration;

/**
 * For races between real processes: a forked process opens its own database
 * connection and sees only committed rows, so these tests cannot run inside
 * a rolled-back transaction. The schema is rebuilt for every test instead.
 */
#[WithMigration]
abstract class ConcurrencyTestCase extends TestbenchPackageTestCase
{
    use DatabaseMigrations;
}
