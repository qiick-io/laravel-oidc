<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Contracts\SecondFactorChallengeContract;
use Qiick\Oidc\Services\Concerns\ChecksTwoFactorSecretTrait;
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
    use ChecksTwoFactorSecretTrait;

    /**
     * The two class names are internal test hooks, so the default challenge
     * is tested without Fortify installed; apps never pass them.
     *
     * @param  string  $fortifyClass  Fortify's facade-like class
     * @param  string  $twoFactorTrait  the trait a user model uses for Fortify's two-factor columns
     */
    public function __construct(
        private bool $isRequiredByDefault,
        private string $fortifyClass = 'Laravel\Fortify\Fortify',
        private string $twoFactorTrait = 'Laravel\Fortify\TwoFactorAuthenticatable',
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
        if (! class_exists($this->fortifyClass) || ! in_array($this->twoFactorTrait, class_uses_recursive($user), true)) {
            return false;
        }

        if (! $this->hasTwoFactorSecret($user)) {
            return false;
        }

        $confirmationCheck = [$this->fortifyClass, 'confirmsTwoFactorAuthentication'];
        $isConfirmationRequired = is_callable($confirmationCheck) && $confirmationCheck() === true;

        return ! $isConfirmationRequired || $user->getAttribute('two_factor_confirmed_at') !== null;
    }
}
