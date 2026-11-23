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
     * @param  int|null  $maxAge  seconds sent as `max_age` (OIDC Core 3.1.2.1); null sends none
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
        public ?int $maxAge = null,
    ) {}

    public function isPublicClient(): bool
    {
        return $this->clientSecret === null || $this->clientSecret === '';
    }
}
