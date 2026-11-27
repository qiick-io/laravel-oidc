<?php

declare(strict_types=1);

namespace Qiick\Oidc\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The app's own second factor for a user whose IdP login lacks signed MFA
 * proof (design section 4, "MFA").
 *
 * The default starts Laravel Fortify's challenge when 2FA is required by
 * `oidc.mfa.required` or the user has enabled it for their own account. Apps
 * can bind an implementation that reads their own enrollment policy.
 */
interface SecondFactorChallengeContract
{
    /**
     * Whether this user must pass a second factor to sign in.
     */
    public function isRequired(Model&Authenticatable $user): bool;

    /**
     * Starts the app's challenge for a user who is not signed in yet. The
     * challenge must end with Auth::login() (the Login event completes the
     * SSO session). Null when the user has no second factor to challenge:
     * the package then signs the user in and the app's own enrollment rules
     * apply, exactly as after a password login.
     */
    public function challenge(Request $request, Model&Authenticatable $user, bool $shouldRemember): ?Response;
}
