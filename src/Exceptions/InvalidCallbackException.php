<?php

declare(strict_types=1);

namespace Qiick\Oidc\Exceptions;

/**
 * The authorization response on the redirect URI cannot be accepted: the IdP
 * returned an error, `state` is missing, unknown, reused or expired, `code` is
 * missing, or the RFC 9207 `iss` parameter names another issuer.
 */
final class InvalidCallbackException extends OidcException {}
