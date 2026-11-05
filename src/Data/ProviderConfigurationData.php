<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

use Qiick\Oidc\Enums\TokenEndpointAuthMethodEnum;

/**
 * The settings of one OIDC provider as the app resolved them, from config or
 * from its own settings table.
 */
final readonly class ProviderConfigurationData
{
    /**
     * @param  list<string>  $scopes  always contains `openid`
     */
    public function __construct(
        public string $issuer,
        public string $clientId,
        #[\SensitiveParameter]
        public ?string $clientSecret,
        public string $redirectUri,
        public array $scopes,
        public TokenEndpointAuthMethodEnum $tokenEndpointAuthMethod = TokenEndpointAuthMethodEnum::ClientSecretBasic,
        public ?string $postLogoutRedirectUri = null,
    ) {}

    public function isPublicClient(): bool
    {
        return $this->clientSecret === null || $this->clientSecret === '';
    }
}
