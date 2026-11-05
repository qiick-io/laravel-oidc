<?php

declare(strict_types=1);

namespace Qiick\Oidc\Exceptions;

/**
 * A server-side call to the IdP (discovery, JWKS, token endpoint) failed, was
 * refused by the SSRF guard, or returned a document the package cannot trust.
 */
final class IdentityProviderRequestException extends OidcException {}
