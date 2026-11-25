<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Qiick\Oidc\Contracts\BreakGlassPolicyContract;

/**
 * Default break-glass policy: one of the configured roles (Spatie `hasRole`)
 * and, unless turned off, a confirmed second factor. The design asks for
 * "super-admin with password + 2FA": a password alone is not enough to get
 * past SSO-only mode.
 */
final readonly class RoleBreakGlassPolicyService implements BreakGlassPolicyContract
{
    /**
     * @param  list<string>  $roles
     */
    public function __construct(
        private array $roles,
        private bool $isTwoFactorRequired,
    ) {}

    public function isBreakGlassAccount(Authenticatable $user): bool
    {
        if (! $user instanceof Model || ! method_exists($user, 'hasRole')) {
            return false;
        }

        $hasBreakGlassRole = array_filter($this->roles, fn (string $role): bool => $user->hasRole($role) === true) !== [];

        if (! $hasBreakGlassRole) {
            return false;
        }

        return ! $this->isTwoFactorRequired || $this->hasConfirmedSecondFactor($user);
    }

    private function hasConfirmedSecondFactor(Model $user): bool
    {
        // The same test as the Fortify challenge: an app may cast the secret
        // to an object, so only null or an empty string means "no second factor".
        $secret = $user->getAttribute('two_factor_secret');

        if ($secret === null || $secret === '') {
            return false;
        }

        $attributes = $user->getAttributes();

        return ! array_key_exists('two_factor_confirmed_at', $attributes) || $attributes['two_factor_confirmed_at'] !== null;
    }
}
