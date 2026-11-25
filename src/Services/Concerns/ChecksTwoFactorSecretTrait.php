<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services\Concerns;

use Illuminate\Database\Eloquent\Model;
use Stringable;

/**
 * One answer to "does this user have a two-factor secret?" for the Fortify
 * challenge and the break-glass policy, so they cannot drift apart.
 *
 * An app may cast the secret (encrypted, AsStringable, a value object):
 * null, an empty string or a value that renders as one means no secret; any
 * other value counts as a secret (fail closed for the challenge).
 *
 * @internal Not part of the public API (docs/PUBLIC-API.md); it can change in any release.
 */
trait ChecksTwoFactorSecretTrait
{
    private function hasTwoFactorSecret(Model $user): bool
    {
        $secret = $user->getAttribute('two_factor_secret');

        if (is_string($secret) || $secret instanceof Stringable) {
            return (string) $secret !== '';
        }

        return $secret !== null;
    }
}
