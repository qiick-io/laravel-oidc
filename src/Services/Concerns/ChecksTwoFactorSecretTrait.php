<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services\Concerns;

use Illuminate\Database\Eloquent\Model;

/**
 * One answer to "does this user have a two-factor secret?" for the Fortify
 * challenge and the break-glass policy, so they cannot drift apart.
 *
 * An app may cast the secret (encrypted, AsStringable, a value object):
 * a blank value (null, whitespace, an empty string, Stringable, array or
 * Countable) means no secret; any other value counts as a secret (fail
 * closed for the challenge).
 *
 * @internal Not part of the public API (docs/public-api.md); it can change in any release.
 */
trait ChecksTwoFactorSecretTrait
{
    private function hasTwoFactorSecret(Model $user): bool
    {
        // blank(): null, whitespace-only strings and Stringables, empty arrays and Countables.
        return ! blank($user->getAttribute('two_factor_secret'));
    }
}
