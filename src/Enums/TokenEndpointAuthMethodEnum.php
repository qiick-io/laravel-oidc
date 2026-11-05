<?php

declare(strict_types=1);

namespace Qiick\Oidc\Enums;

/**
 * Client authentication at the token endpoint (OIDC Core 9). A client without a
 * secret is a public client and authenticates with PKCE alone.
 */
enum TokenEndpointAuthMethodEnum: string
{
    case ClientSecretBasic = 'client_secret_basic';
    case ClientSecretPost = 'client_secret_post';
}
