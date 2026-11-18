<?php

declare(strict_types=1);

namespace Qiick\Oidc\Exceptions;

/**
 * A JWT from the IdP failed validation: format, algorithm, signature, or one of
 * the claims checked by OIDC Core 3.1.3.7.
 */
final class InvalidTokenException extends OidcException {}
