<?php

declare(strict_types=1);

namespace Qiick\Oidc\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Decides which local accounts keep password login in SSO-only mode. The
 * default qualifies `oidc.break_glass.roles` with a confirmed second factor;
 * an app with another notion of owner binds its own.
 */
interface BreakGlassPolicyContract
{
    public function isBreakGlassAccount(Authenticatable $user): bool;
}
