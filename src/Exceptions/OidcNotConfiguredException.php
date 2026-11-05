<?php

declare(strict_types=1);

namespace Qiick\Oidc\Exceptions;

/**
 * SSO is turned off, or the issuer or client id is missing.
 */
final class OidcNotConfiguredException extends OidcException {}
