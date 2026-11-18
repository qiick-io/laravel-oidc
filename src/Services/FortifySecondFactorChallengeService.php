<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Contracts\SecondFactorChallengeContract;
use Symfony\Component\HttpFoundation\Response;

/**
 * Default second factor: Laravel Fortify's two-factor challenge, started the
 * way Fortify's own login pipeline starts it (`login.id` and `login.remember`
 * in the session, then the `two-factor.login` route). The package does not
 * depend on Fortify: without it, or without a confirmed TOTP secret on the
 * user, there is nothing to challenge.
 */
final readonly class FortifySecondFactorChallengeService implements SecondFactorChallengeContract
{
    private const string FORTIFY_CLASS = 'Laravel\Fortify\Fortify';

    private const string TWO_FACTOR_TRAIT = 'Laravel\Fortify\TwoFactorAuthenticatable';

    public function __construct(
        private bool $isRequiredByDefault,
    ) {}

    public function isRequired(Model&Authenticatable $user): bool
    {
        return $this->isRequiredByDefault;
    }

    public function challenge(Request $request, Model&Authenticatable $user, bool $shouldRemember): ?Response
    {
        if (! $this->hasConfirmedFortifySecondFactor($user) || ! Route::has('two-factor.login')) {
            return null;
        }

        $request->session()->put([
            'login.id' => $user->getKey(),
            'login.remember' => $shouldRemember,
        ]);

        return new RedirectResponse(route('two-factor.login'));
    }

    private function hasConfirmedFortifySecondFactor(Model $user): bool
    {
        if (! class_exists(self::FORTIFY_CLASS) || ! in_array(self::TWO_FACTOR_TRAIT, class_uses_recursive($user), true)) {
            return false;
        }

        if (in_array($user->getAttribute('two_factor_secret'), [null, ''], true)) {
            return false;
        }

        $confirmationCheck = [self::FORTIFY_CLASS, 'confirmsTwoFactorAuthentication'];
        $isConfirmationRequired = is_callable($confirmationCheck) && (bool) $confirmationCheck();

        return ! $isConfirmationRequired || $user->getAttribute('two_factor_confirmed_at') !== null;
    }
}
