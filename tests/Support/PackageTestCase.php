<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support;

use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Orchestra\Testbench\Attributes\WithMigration;

/**
 * The default test case: every test runs in a transaction that is rolled
 * back, so tests never see each other's rows.
 */
#[WithMigration]
abstract class PackageTestCase extends TestbenchPackageTestCase
{
    use LazilyRefreshDatabase;
}
