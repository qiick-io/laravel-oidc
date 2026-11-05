<?php

declare(strict_types=1);

namespace Qiick\Oidc\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The app's own second factor, used when the app requires 2FA and the IdP
 * cannot prove MFA happened (design section 4, "MFA").
 *
 * The default reads `oidc.mfa.required` and starts Laravel Fortify's
 * two-factor challenge. Externa and Excubia App bind an implementation that
 * reads their `two_factor_required` setting.
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
