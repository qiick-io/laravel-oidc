<?php

declare(strict_types=1);

namespace Qiick\Oidc\Laravel;

use Illuminate\Support\ServiceProvider;

/**
 * Registers the package in a Laravel app. Auto-discovered through
 * `extra.laravel.providers` in composer.json.
 *
 * The provider only wires configuration for now. Routes, migrations and the
 * `oidc:configure` command are registered here as they land.
 */
final class OidcServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/oidc.php', 'oidc');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../config/oidc.php' => config_path('oidc.php'),
            ], 'oidc-config');
        }
    }
}
