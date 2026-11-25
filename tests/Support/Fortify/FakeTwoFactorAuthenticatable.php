<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support\Fortify;

/**
 * Stands in for Laravel\Fortify\TwoFactorAuthenticatable: the challenge
 * service only checks that the user model uses it.
 */
trait FakeTwoFactorAuthenticatable {}
