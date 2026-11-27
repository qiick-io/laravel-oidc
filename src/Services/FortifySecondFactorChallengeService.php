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
 * in the session, then the `two-factor.login` route). A self-enrolled second
 * factor carries over to SSO even when the app does not require enrollment.
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
        return $this->isRequiredByDefault || $this->hasConfirmedFortifySecondFactor($user);
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

    /**
     * The deploy check uses the same confirmation rule as the live challenge.
     *
     * @param  class-string<Model>  $userModel
     *
     * @internal
     */
    public function hasAvailableEnrollment(string $userModel, ?string $activeColumn): bool
    {
        if (! Route::has('two-factor.login') || ! $this->hasFortifyUserModel($userModel)) {
            return false;
        }

        return $userModel::query()->whereNotNull('two_factor_secret')->cursor()->contains(
            fn (Model $user): bool => ($activeColumn === null || $user->getAttribute($activeColumn))
                && $this->hasConfirmedFortifySecondFactor($user),
        );
    }

    private function hasConfirmedFortifySecondFactor(Model $user): bool
    {
        if (! $this->hasFortifyUserModel($user)) {
            return false;
        }

        if (! $this->hasTwoFactorSecret($user)) {
            return false;
        }

        $confirmationCheck = [$this->fortifyClass, 'confirmsTwoFactorAuthentication'];
        $isConfirmationRequired = is_callable($confirmationCheck) && $confirmationCheck() === true;

        return ! $isConfirmationRequired || $user->getAttribute('two_factor_confirmed_at') !== null;
    }

    /** @param Model|class-string<Model> $userModel */
    private function hasFortifyUserModel(Model|string $userModel): bool
    {
        return class_exists($this->fortifyClass) && in_array($this->twoFactorTrait, class_uses_recursive($userModel), true);
    }
}
