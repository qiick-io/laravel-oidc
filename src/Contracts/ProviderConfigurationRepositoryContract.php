<?php

declare(strict_types=1);

namespace Qiick\Oidc\Contracts;

use Qiick\Oidc\Data\ProviderConfigurationData;
use Qiick\Oidc\Exceptions\OidcNotConfiguredException;

/**
 * Where the package reads the provider settings from.
 *
 * The default implementation reads `config/oidc.php`. An app that keeps its
 * OIDC settings in the database (Externa's project settings, Excubia App's
 * settings table) binds its own implementation in a service provider.
 */
interface ProviderConfigurationRepositoryContract
{
    /**
     * True when SSO is on and the issuer and client id are set.
     */
    public function isEnabled(): bool;

    /**
     * @throws OidcNotConfiguredException when isEnabled() is false
     */
    public function configuration(): ProviderConfigurationData;
}
