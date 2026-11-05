<?php

declare(strict_types=1);

namespace Qiick\Oidc\Laravel;

use Illuminate\Cache\CacheManager;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\ServiceProvider;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Repositories\ConfigProviderConfigurationRepository;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Services\IdentityProviderHttpService;
use Qiick\Oidc\Services\JwksService;
use Qiick\Oidc\Services\JwtValidatorService;
use Qiick\Oidc\Services\RemoteUrlGuardService;

/**
 * Registers the package in a Laravel app. Auto-discovered through
 * `extra.laravel.providers` in composer.json.
 *
 * Services are bound, not shared, so each resolution reads the current config
 * (an app can change the OIDC settings at runtime from its settings UI). The
 * SSRF guard is the exception: it is shared so tests and the fake IdP can swap
 * its DNS resolver.
 *
 * An app that keeps OIDC settings in its database binds its own
 * ProviderConfigurationRepositoryContract after this provider.
 */
final class OidcServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/oidc.php', 'oidc');

        $this->app->bind(ProviderConfigurationRepositoryContract::class, ConfigProviderConfigurationRepository::class);

        $this->app->singleton(RemoteUrlGuardService::class, fn (Application $app): RemoteUrlGuardService => new RemoteUrlGuardService(
            isPrivateHostAllowed: $this->config($app)->boolean('oidc.http.allow_private_hosts'),
            hostResolver: RemoteUrlGuardService::resolveWithSystemDns(...),
        ));

        $this->app->bind(IdentityProviderHttpService::class, fn (Application $app): IdentityProviderHttpService => new IdentityProviderHttpService(
            http: $app->make(HttpFactory::class),
            remoteUrlGuard: $app->make(RemoteUrlGuardService::class),
            timeoutSeconds: $this->config($app)->integer('oidc.http.timeout', 10),
        ));

        $this->app->bind(DiscoveryService::class, fn (Application $app): DiscoveryService => new DiscoveryService(
            identityProviderHttp: $app->make(IdentityProviderHttpService::class),
            remoteUrlGuard: $app->make(RemoteUrlGuardService::class),
            cache: $this->cacheStore($app),
            cacheSeconds: $this->config($app)->integer('oidc.cache.discovery_ttl', 21600),
            discoveryBase: $this->optionalString($app, 'oidc.http.discovery_base'),
            serverOrigin: $this->optionalString($app, 'oidc.http.server_origin'),
        ));

        $this->app->bind(JwksService::class, fn (Application $app): JwksService => new JwksService(
            identityProviderHttp: $app->make(IdentityProviderHttpService::class),
            cache: $this->cacheStore($app),
            cacheSeconds: $this->config($app)->integer('oidc.cache.jwks_ttl', 3600),
            refetchCooldownSeconds: $this->config($app)->integer('oidc.cache.jwks_refetch_cooldown', 30),
        ));

        $this->app->bind(JwtValidatorService::class, fn (Application $app): JwtValidatorService => new JwtValidatorService(
            jwks: $app->make(JwksService::class),
            allowedAlgorithms: $this->stringList($app, 'oidc.id_token.algorithms'),
            leewaySeconds: $this->config($app)->integer('oidc.id_token.leeway', 60),
            trustedAudiences: $this->stringList($app, 'oidc.id_token.trusted_audiences'),
        ));
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../config/oidc.php' => config_path('oidc.php'),
            ], 'oidc-config');
        }
    }

    private function config(Application $app): ConfigRepository
    {
        return $app->make(ConfigRepository::class);
    }

    private function cacheStore(Application $app): CacheRepository
    {
        $storeName = $this->optionalString($app, 'oidc.cache.store');

        return $app->make(CacheManager::class)->store($storeName);
    }

    private function optionalString(Application $app, string $key): ?string
    {
        $value = $this->config($app)->get($key);

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    /**
     * @return list<string>
     */
    private function stringList(Application $app, string $key): array
    {
        return array_values(array_filter($this->config($app)->array($key, []), is_string(...)));
    }
}
