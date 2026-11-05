<?php

declare(strict_types=1);

namespace Qiick\Oidc\Exceptions;

use RuntimeException;

/**
 * Base class of every exception the package throws, so an app can catch one
 * type around the SSO login and fall back to its own login form.
 *
 * Messages are safe to log: they never contain tokens, codes, secrets or
 * claim values. They are not meant to be shown to end users as they are.
 */
abstract class OidcException extends RuntimeException {}
