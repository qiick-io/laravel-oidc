<?php

declare(strict_types=1);

namespace Qiick\Oidc\Listeners;

use Illuminate\Auth\Events\Validated;
use Illuminate\Validation\ValidationException;
use Qiick\Oidc\Services\SsoOnlyModeService;

/**
 * Refuses a password login in SSO-only mode for everyone but break-glass
 * accounts. `Validated` fires inside Auth::attempt() after the password was
 * checked and before the session is touched, so throwing here leaves the user
 * signed out.
 */
final readonly class EnforceSsoOnlyListener
{
    public function __construct(
        private SsoOnlyModeService $ssoOnlyMode,
    ) {}

    /**
     * @throws ValidationException
     */
    public function handle(Validated $event): void
    {
        if (! $this->ssoOnlyMode->canUseLocalLogin($event->user)) {
            throw ValidationException::withMessages([
                'email' => __('Password sign-in is disabled. Use single sign-on.'),
            ]);
        }
    }
}
