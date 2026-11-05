<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support;

use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase;
use Qiick\Oidc\Laravel\OidcServiceProvider;

/**
 * Boots a Testbench Laravel app with the package provider. CI runs the suite
 * on Laravel 12 and 13.
 */
abstract class PackageTestCase extends TestCase
{
    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [OidcServiceProvider::class];
    }
}
