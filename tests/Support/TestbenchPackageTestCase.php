<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\Attributes\WithMigration;
use Orchestra\Testbench\TestCase;
use Qiick\Oidc\Laravel\OidcServiceProvider;

/**
 * Boots a Testbench Laravel app with the package provider, without choosing
 * how the database is reset: PackageTestCase wraps each test in a
 * transaction, ConcurrencyTestCase commits for real so a second process can
 * see the rows. CI runs the suite on Laravel 12 and 13.
 */
#[WithMigration]
abstract class TestbenchPackageTestCase extends TestCase
{
    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [OidcServiceProvider::class];
    }

    /**
     * Install the host's active flag before Laravel opens the test transaction.
     * Adding a column inside it implicitly commits on MySQL and MariaDB.
     */
    protected function defineDatabaseMigrationsAfterDatabaseRefreshed(): void
    {
        Schema::table('users', fn (Blueprint $table) => $table->boolean('is_active')->default(true));
    }

    /**
     * The web group encrypts cookies, so the app needs a key. It is random
     * per run: nothing secret is committed.
     *
     * The database is in-memory SQLite unless the process environment names
     * another connection: CI runs the suite on MySQL and MariaDB as well,
     * because their default collations compare the identity key differently.
     *
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('database.default', getenv('DB_CONNECTION') ?: 'testing');
        $app['config']->set('auth.providers.users.model', User::class);
    }
}
