<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Feature;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Tests\Support\PackageTestCase;

/**
 * S4: oidc.routes.except must be applied at boot, so the config is set before
 * the application is created (Config::set after boot is too late for routes).
 */
final class RoutesExceptTest extends PackageTestCase
{
    public function test_skips_package_routes_listed_in_except(): void
    {
        $this->assertFalse(Route::has('oidc.callback'));
        $this->assertTrue(Route::has('oidc.redirect'));
        $this->assertTrue(Route::has('oidc.backchannel-logout'));
        $this->assertTrue(Route::has('oidc.frontchannel-logout'));
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('oidc.enabled', true);
        $app['config']->set('oidc.issuer', 'https://idp.example.com/realms/test');
        $app['config']->set('oidc.client_id', 'laravel-app');
        $app['config']->set('oidc.routes.except', ['oidc.callback']);
    }
}
