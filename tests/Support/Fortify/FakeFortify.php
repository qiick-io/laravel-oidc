<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support\Fortify;

/**
 * Stands in for Laravel\Fortify\Fortify, which this package does not depend
 * on: only the confirmation feature switch the challenge service reads.
 */
final class FakeFortify
{
    public static bool $isConfirmationRequired = true;

    public static function confirmsTwoFactorAuthentication(): bool
    {
        return self::$isConfirmationRequired;
    }
}
