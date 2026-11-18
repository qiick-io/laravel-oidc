<?php

declare(strict_types=1);

namespace Qiick\Oidc\Exceptions;

use Qiick\Oidc\Enums\LoginRefusalReasonEnum;

/**
 * The IdP authenticated the user, but the app refuses the login: no linked
 * user, linking not allowed, inactive user, and so on. The message is safe to
 * show to the user.
 */
final class LoginRefusedException extends OidcException
{
    public function __construct(public readonly LoginRefusalReasonEnum $reason)
    {
        parent::__construct($reason->message());
    }
}
