<?php

declare(strict_types=1);

namespace Qiick\Oidc\Laravel;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Cache\CacheManager;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel as HttpKernelContract;
use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Qiick\Oidc\Console\ConfigureOidcCommand;
use Qiick\Oidc\Console\ImportLegacySubjectsCommand;
use Qiick\Oidc\Console\PruneLogoutRevocationsCommand;
use Qiick\Oidc\Contracts\BreakGlassPolicyContract;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Contracts\RoleSynchronizationContract;
use Qiick\Oidc\Contracts\SecondFactorChallengeContract;
use Qiick\Oidc\Contracts\UserClaimSynchronizationContract;
use Qiick\Oidc\Contracts\UserProvisioningContract;
use Qiick\Oidc\Factories\OidcOutboundStackFactory;
use Qiick\Oidc\Http\Middleware\EnsureOidcSessionIsActiveMiddleware;
use Qiick\Oidc\Listeners\EnforceSsoOnlyListener;
use Qiick\Oidc\Listeners\PromotePendingIdentityListener;
use Qiick\Oidc\Repositories\ConfigProviderConfigurationRepository;
use Qiick\Oidc\Services\AuthorizationCodeFlowService;
use Qiick\Oidc\Services\BackChannelLogoutService;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Services\EloquentUserProvisioningService;
use Qiick\Oidc\Services\FortifySecondFactorChallengeService;
use Qiick\Oidc\Services\IdentityProviderHttpService;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Services\IdTokenValidatorService;
use Qiick\Oidc\Services\JwksService;
use Qiick\Oidc\Services\JwtValidatorService;
use Qiick\Oidc\Services\MultiFactorClaimService;
use Qiick\Oidc\Services\NullUserClaimSynchronizationService;
use Qiick\Oidc\Services\OidcLoginService;
use Qiick\Oidc\Services\RoleBreakGlassPolicyService;
use Qiick\Oidc\Services\RoleMappingService;
use Qiick\Oidc\Services\SessionRevocationService;
use Qiick\Oidc\Services\SpatieRoleSynchronizationService;
use Qiick\Oidc\Services\SsoOnlyModeService;
use Qiick\Oidc\Services\UserinfoService;
use Qiick\Oidc\Services\UserLinkingService;
use Qiick\Outbound\Ssrf\DnsHostResolver;

/**
 * Registers the package in a Laravel app. Auto-discovered through
 * `extra.laravel.providers` in composer.json.
 *
 * Services are bound, not shared, so each resolution reads the current config
 * (an app can change the OIDC settings at runtime from its settings UI).
 *
 * IdP HTTP SSRF / pinning / timeouts are built by {@see OidcOutboundStackFactory}
 * privately, so alphabetical package discovery cannot let outbound rebind them.
 * Tests swap DNS through {@see OidcOutboundStackFactory::HostResolverBinding}.
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

        $this->app->bind(OidcOutboundStackFactory::HostResolverBinding, DnsHostResolver::class);

        $this->app->bind(OidcOutboundStackFactory::class, fn (Application $app): OidcOutboundStackFactory => new OidcOutboundStackFactory(
            http: $app->make(HttpFactory::class),
            config: $this->config($app),
            hostResolver: $app->make(OidcOutboundStackFactory::HostResolverBinding),
        ));

        $this->app->bind(IdentityProviderHttpService::class, function (Application $app): IdentityProviderHttpService {
            $stack = $app->make(OidcOutboundStackFactory::class)->make();

            return new IdentityProviderHttpService(
                pinnedHttp: $stack->pinnedHttp,
                urlGuardOptions: $stack->urlGuardOptions,
                timeoutSeconds: $this->config($app)->integer('oidc.http.timeout', 10),
                connectTimeoutSeconds: $this->config($app)->integer('oidc.http.connect_timeout', 10),
                maxResponseBytes: max(1, $this->config($app)->integer('oidc.http.max_response_bytes', 1_048_576)),
            );
        });

        $this->app->bind(DiscoveryService::class, function (Application $app): DiscoveryService {
            $stack = $app->make(OidcOutboundStackFactory::class)->make();

            return new DiscoveryService(
                identityProviderHttp: $app->make(IdentityProviderHttpService::class),
                remoteUrlGuard: $stack->remoteUrlGuard,
                urlGuardOptions: $stack->urlGuardOptions,
                cache: $this->cacheStore($app),
                cacheSeconds: $this->config($app)->integer('oidc.cache.discovery_ttl', 21600),
                discoveryBase: $this->optionalString($app, 'oidc.http.discovery_base'),
                serverOrigin: $this->optionalString($app, 'oidc.http.server_origin'),
            );
        });

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

        $this->app->bind(AuthorizationCodeFlowService::class, fn (Application $app): AuthorizationCodeFlowService => new AuthorizationCodeFlowService(
            configurationRepository: $app->make(ProviderConfigurationRepositoryContract::class),
            discovery: $app->make(DiscoveryService::class),
            identityProviderHttp: $app->make(IdentityProviderHttpService::class),
            idTokenValidator: $app->make(IdTokenValidatorService::class),
            userinfo: $app->make(UserinfoService::class),
            shouldFetchUserinfo: $this->config($app)->boolean('oidc.userinfo', true),
            leewaySeconds: $this->config($app)->integer('oidc.id_token.leeway', 60),
            isRequestedAcrRequired: $this->config($app)->boolean('oidc.mfa.require_requested_acr'),
        ));

        $this->app->bind(UserProvisioningContract::class, EloquentUserProvisioningService::class);

        $this->app->bind(UserLinkingService::class, fn (Application $app): UserLinkingService => new UserLinkingService(
            userProvisioning: $app->make(UserProvisioningContract::class),
            events: $app->make(Dispatcher::class),
            isAutoLinkEnabled: $this->config($app)->boolean('oidc.auto_link'),
            isJitEnabled: $this->config($app)->boolean('oidc.jit'),
            isVerifiedEmailRequired: $this->config($app)->boolean('oidc.require_verified_email', true),
            allowedDomains: array_map(mb_strtolower(...), $this->stringList($app, 'oidc.allowed_domains')),
            emailColumn: $this->optionalString($app, 'oidc.users.email_column') ?? 'email',
            activeColumn: $this->optionalString($app, 'oidc.users.active_column'),
        ));

        $this->app->bind(RoleSynchronizationContract::class, SpatieRoleSynchronizationService::class);

        $this->app->bind(UserClaimSynchronizationContract::class, NullUserClaimSynchronizationService::class);

        $this->app->bind(RoleMappingService::class, fn (Application $app): RoleMappingService => new RoleMappingService(
            roleSynchronization: $app->make(RoleSynchronizationContract::class),
            isEnabled: $this->config($app)->boolean('oidc.roles.enabled'),
            claimPath: $this->optionalString($app, 'oidc.roles.claim') ?? 'orgs',
            organization: $this->optionalString($app, 'oidc.roles.organization'),
            roleMap: $this->roleMap($app),
            forbiddenRoles: $this->stringList($app, 'oidc.roles.forbidden'),
        ));

        $this->app->bind(SecondFactorChallengeContract::class, fn (Application $app): SecondFactorChallengeContract => new FortifySecondFactorChallengeService(
            isRequiredByDefault: $this->config($app)->boolean('oidc.mfa.required'),
        ));

        $this->app->bind(MultiFactorClaimService::class, fn (Application $app): MultiFactorClaimService => new MultiFactorClaimService(
            acceptedAmrValues: $this->stringList($app, 'oidc.mfa.amr_values'),
            acceptedAcrValues: $this->stringList($app, 'oidc.mfa.acr_values'),
        ));

        $this->app->bind(OidcLoginService::class, fn (Application $app): OidcLoginService => new OidcLoginService(
            userLinking: $app->make(UserLinkingService::class),
            roleMapping: $app->make(RoleMappingService::class),
            userClaimSynchronization: $app->make(UserClaimSynchronizationContract::class),
            multiFactorClaims: $app->make(MultiFactorClaimService::class),
            secondFactorChallenge: $app->make(SecondFactorChallengeContract::class),
            identitySession: $app->make(IdentitySessionService::class),
            auth: $app->make(AuthFactory::class),
            events: $app->make(Dispatcher::class),
            shouldRemember: $this->config($app)->boolean('oidc.remember'),
        ));

        $this->app->bind(BreakGlassPolicyContract::class, fn (Application $app): BreakGlassPolicyContract => new RoleBreakGlassPolicyService(
            roles: $this->stringList($app, 'oidc.break_glass.roles'),
            isTwoFactorRequired: $this->config($app)->boolean('oidc.break_glass.require_two_factor', true),
        ));

        $this->app->bind(SsoOnlyModeService::class, fn (Application $app): SsoOnlyModeService => new SsoOnlyModeService(
            configurationRepository: $app->make(ProviderConfigurationRepositoryContract::class),
            breakGlassPolicy: $app->make(BreakGlassPolicyContract::class),
            isOnlyModeConfigured: $this->config($app)->boolean('oidc.only'),
            buttonLabel: $this->optionalString($app, 'oidc.button_label'),
            breakGlassQueryParameter: $this->optionalString($app, 'oidc.break_glass.query_parameter') ?? 'local',
        ));

        $this->app->bind(SessionRevocationService::class, fn (Application $app): SessionRevocationService => new SessionRevocationService(
            cache: $this->cacheStore($app),
            revocationSeconds: $this->revocationSeconds($app),
            events: $app->make(Dispatcher::class),
        ));

        $this->app->bind(BackChannelLogoutService::class, fn (Application $app): BackChannelLogoutService => new BackChannelLogoutService(
            configurationRepository: $app->make(ProviderConfigurationRepositoryContract::class),
            discovery: $app->make(DiscoveryService::class),
            jwtValidator: $app->make(JwtValidatorService::class),
            sessionRevocation: $app->make(SessionRevocationService::class),
            cache: $this->cacheStore($app),
        ));
    }

    public function boot(): void
    {
        $this->app->make(Dispatcher::class)->listen(Login::class, PromotePendingIdentityListener::class);
        $this->app->make(Dispatcher::class)->listen(Validated::class, EnforceSsoOnlyListener::class);

        $this->loadMigrationsFrom(__DIR__.'/../../database/migrations');

        $httpKernel = $this->app->make(HttpKernelContract::class);

        if ($httpKernel instanceof HttpKernel) {
            // Through the kernel, not the router: the kernel re-syncs its groups onto the router.
            $httpKernel->appendMiddlewareToGroup('web', EnsureOidcSessionIsActiveMiddleware::class);

            // Appending to the group is not enough. The priority list reorders the group, and
            // `auth` is in that list while this middleware is not, so `auth` would run first:
            // the request after a back-channel logout would pass `auth` and reach the controller
            // with a session the identity provider has already ended. Insert it immediately
            // before `auth` — not at the head of the list, which would also put it before
            // `StartSession`, where there is no session to inspect and it silently does nothing.
            $httpKernel->addToMiddlewarePriorityBefore(
                AuthenticatesRequests::class,
                EnsureOidcSessionIsActiveMiddleware::class,
            );
        }

        if ($this->config($this->app)->boolean('oidc.routes.enabled', true) && ! $this->app->routesAreCached()) {
            Route::prefix($this->optionalString($this->app, 'oidc.routes.prefix') ?? 'auth/oidc')
                ->group(__DIR__.'/../../routes/oidc.php');
        }

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../config/oidc.php' => config_path('oidc.php'),
            ], 'oidc-config');

            $this->commands([
                ConfigureOidcCommand::class,
                ImportLegacySubjectsCommand::class,
                PruneLogoutRevocationsCommand::class,
            ]);

            $this->publishesMigrations([
                __DIR__.'/../../database/migrations' => database_path('migrations'),
            ], 'oidc-migrations');
        }
    }

    /**
     * Max of the configured lifetimes so a short `revocation_ttl` cannot
     * under-cover `session.lifetime`. Null `revocation_ttl` uses session only.
     */
    private function revocationSeconds(Application $app): int
    {
        $sessionLifetimeSeconds = max(1, $this->config($app)->integer('session.lifetime', 120)) * 60;
        $configuredSeconds = $this->config($app)->get('oidc.backchannel_logout.revocation_ttl');

        if (is_int($configuredSeconds) && $configuredSeconds > 0) {
            return max($configuredSeconds, $sessionLifetimeSeconds);
        }

        return $sessionLifetimeSeconds;
    }

    /**
     * `oidc.roles.map` with every value normalised to a list of role names.
     *
     * @return array<string, list<string>>
     */
    private function roleMap(Application $app): array
    {
        $roleMap = [];

        foreach ($this->config($app)->array('oidc.roles.map', []) as $identityProviderRole => $appRoles) {
            $appRoleList = array_values(array_filter(is_array($appRoles) ? $appRoles : [$appRoles], is_string(...)));

            if (is_string($identityProviderRole) && $appRoleList !== []) {
                $roleMap[$identityProviderRole] = $appRoleList;
            }
        }

        return $roleMap;
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
