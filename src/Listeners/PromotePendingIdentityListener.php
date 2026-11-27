<?php

declare(strict_types=1);

namespace Qiick\Oidc\Listeners;

use Illuminate\Auth\Events\Login;
use Illuminate\Http\Request;
use Qiick\Oidc\Services\IdentitySessionService;

/**
 * Completes an SSO login that went through the app's own second factor: when
 * the challenge signs the user in, the parked SSO identity becomes the
 * session identity.
 *
 * @internal Not part of the public API (docs/public-api.md); it can change in any release.
 */
final readonly class PromotePendingIdentityListener
{
    public function __construct(
        private Request $request,
        private IdentitySessionService $identitySession,
    ) {}

    public function handle(Login $event): void
    {
        if (! $this->request->hasSession()) {
            return;
        }

        $userId = $event->user->getAuthIdentifier();

        if (is_int($userId) || is_string($userId)) {
            $this->identitySession->promotePending($this->request->session(), $userId);
        }
    }
}
