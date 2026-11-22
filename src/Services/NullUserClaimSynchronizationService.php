<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Qiick\Oidc\Contracts\UserClaimSynchronizationContract;
use Qiick\Oidc\Data\AuthenticatedIdentityData;

/**
 * Default claim synchroniser: does nothing (standards review S9).
 *
 * Products that should refresh profile fields after login bind their own
 * UserClaimSynchronizationContract implementation instead.
 */
final readonly class NullUserClaimSynchronizationService implements UserClaimSynchronizationContract
{
    public function synchronize(Model&Authenticatable $user, AuthenticatedIdentityData $identity): void {}
}
