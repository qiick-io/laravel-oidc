<?php

declare(strict_types=1);

namespace Qiick\Oidc\Repositories;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Data\ProviderConfigurationData;
use Qiick\Oidc\Enums\TokenEndpointAuthMethodEnum;
use Qiick\Oidc\Exceptions\OidcNotConfiguredException;

/**
 * Reads the provider settings from `config/oidc.php` (env vars `OIDC_*`).
 */
final readonly class ConfigProviderConfigurationRepository implements ProviderConfigurationRepositoryContract
{
    public const DEFAULT_CALLBACK_PATH = 'auth/oidc/callback';

    public function __construct(
        private ConfigRepository $config,
        private UrlGenerator $urlGenerator,
    ) {}

    public function isEnabled(): bool
    {
        return $this->config->get('oidc.enabled') === true
            && $this->string('oidc.issuer') !== null
            && $this->string('oidc.client_id') !== null;
    }

    public function configuration(): ProviderConfigurationData
    {
        $notConfigured = new OidcNotConfiguredException('OIDC is disabled or the issuer or client id is missing.');

        if (! $this->isEnabled()) {
            throw $notConfigured;
        }

        $configuredScopes = $this->config->get('oidc.scopes');
        $scopes = is_array($configuredScopes)
            ? array_filter($configuredScopes, fn (mixed $scope): bool => is_string($scope) && $scope !== '')
            : [];

        $tokenEndpointAuthMethod = $this->string('oidc.token_endpoint_auth_method');

        return new ProviderConfigurationData(
            issuer: $this->string('oidc.issuer') ?? throw $notConfigured,
            clientId: $this->string('oidc.client_id') ?? throw $notConfigured,
            clientSecret: $this->string('oidc.client_secret'),
            redirectUri: $this->string('oidc.redirect_uri') ?? $this->urlGenerator->to(self::DEFAULT_CALLBACK_PATH),
            scopes: array_values(array_unique(['openid', ...$scopes])),
            tokenEndpointAuthMethod: ($tokenEndpointAuthMethod === null ? null : TokenEndpointAuthMethodEnum::tryFrom($tokenEndpointAuthMethod))
                ?? TokenEndpointAuthMethodEnum::ClientSecretBasic,
            postLogoutRedirectUri: $this->string('oidc.post_logout_redirect_uri') ?? $this->defaultPostLogoutRedirectUri(),
            maxAge: $this->nonNegativeInteger('oidc.mfa.max_age'),
        );
    }

    /**
     * The package's post-logout return route, which checks the logout state
     * (standards review S7), or the app root when the app left that route
     * out through `oidc.routes.except` or `oidc.routes.enabled`.
     */
    private function defaultPostLogoutRedirectUri(): string
    {
        return Route::has('oidc.logged-out') ? $this->urlGenerator->route('oidc.logged-out') : $this->urlGenerator->to('/');
    }

    /**
     * A whole number of seconds of zero or more, or null when unset or
     * malformed. Env vars arrive as strings, so a digit string counts too.
     */
    private function nonNegativeInteger(string $key): ?int
    {
        return filter_var($this->config->get($key), FILTER_VALIDATE_INT, ['options' => ['min_range' => 0], 'flags' => FILTER_NULL_ON_FAILURE]);
    }

    /**
     * A trimmed non-empty string, or null. Env vars arrive as strings and an
     * unset one as null or "", so both mean "not configured".
     */
    private function string(string $key): ?string
    {
        $value = $this->config->get($key);

        if (! is_string($value) || trim($value) === '') {
            return null;
        }

        return trim($value);
    }
}
