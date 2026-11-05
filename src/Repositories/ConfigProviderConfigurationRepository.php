<?php

declare(strict_types=1);

namespace Qiick\Oidc\Repositories;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Routing\UrlGenerator;
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
        if (! $this->isEnabled()) {
            throw new OidcNotConfiguredException('OIDC is disabled or the issuer or client id is missing.');
        }

        $configuredScopes = $this->config->get('oidc.scopes');
        $scopes = is_array($configuredScopes)
            ? array_values(array_filter($configuredScopes, fn (mixed $scope): bool => is_string($scope) && $scope !== ''))
            : [];

        return new ProviderConfigurationData(
            issuer: (string) $this->string('oidc.issuer'),
            clientId: (string) $this->string('oidc.client_id'),
            clientSecret: $this->string('oidc.client_secret'),
            redirectUri: $this->string('oidc.redirect_uri') ?? $this->urlGenerator->to(self::DEFAULT_CALLBACK_PATH),
            scopes: array_values(array_unique(['openid', ...$scopes])),
            tokenEndpointAuthMethod: TokenEndpointAuthMethodEnum::tryFrom((string) $this->string('oidc.token_endpoint_auth_method'))
                ?? TokenEndpointAuthMethodEnum::ClientSecretBasic,
            postLogoutRedirectUri: $this->string('oidc.post_logout_redirect_uri') ?? $this->urlGenerator->to('/'),
        );
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
