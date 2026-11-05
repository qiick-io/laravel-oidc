<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Contracts\BreakGlassPolicyContract;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Data\LoginOptionsData;

/**
 * SSO-only mode (`OIDC_ONLY`, design section 4): the login page shows only the
 * SSO button and local logins are refused, except for break-glass accounts.
 *
 * The mode is active only while SSO itself is configured, so turning SSO off
 * (or a missing issuer) can never lock everyone out.
 *
 * Enforcement: the package refuses password logins that go through
 * `Auth::attempt()` (EnforceSsoOnlyListener). Apps whose login bypasses
 * attempt() (Fortify::authenticateUsing(), passkeys) call canUseLocalLogin()
 * in those callbacks.
 */
final readonly class SsoOnlyModeService
{
    public function __construct(
        private ProviderConfigurationRepositoryContract $configurationRepository,
        private BreakGlassPolicyContract $breakGlassPolicy,
        private bool $isOnlyModeConfigured,
        private ?string $buttonLabel,
        private string $breakGlassQueryParameter,
    ) {}

    public function isActive(): bool
    {
        return $this->isOnlyModeConfigured && $this->configurationRepository->isEnabled();
    }

    /**
     * Whether this user may sign in with a local factor (password, passkey).
     */
    public function canUseLocalLogin(Authenticatable $user): bool
    {
        return ! $this->isActive() || $this->breakGlassPolicy->isBreakGlassAccount($user);
    }

    public function loginOptions(Request $request): LoginOptionsData
    {
        $isSsoAvailable = $this->configurationRepository->isEnabled();
        $isSsoOnly = $this->isActive();

        return new LoginOptionsData(
            isSsoAvailable: $isSsoAvailable,
            isSsoOnly: $isSsoOnly,
            isPasswordLoginVisible: ! $isSsoOnly || $request->boolean($this->breakGlassQueryParameter),
            buttonLabel: $this->buttonLabel ?? __('Sign in with SSO'),
            redirectUrl: $isSsoAvailable && Route::has('oidc.redirect') ? route('oidc.redirect') : null,
        );
    }
}
