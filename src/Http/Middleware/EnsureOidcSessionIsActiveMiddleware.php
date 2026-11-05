<?php

declare(strict_types=1);

namespace Qiick\Oidc\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Services\SessionRevocationService;
use Symfony\Component\HttpFoundation\Response;

/**
 * Ends a local session whose IdP session was closed by a back-channel logout.
 *
 * The package pushes it onto the `web` group. It does nothing for local
 * logins (no SSO identity in the session). When the session was revoked it
 * logs the user out of the default guard (which also cycles the remember
 * token), invalidates the session and lets the request continue as a guest,
 * so the app's own `auth` middleware decides where to send the user.
 */
final readonly class EnsureOidcSessionIsActiveMiddleware
{
    public function __construct(
        private AuthFactory $auth,
        private IdentitySessionService $identitySession,
        private SessionRevocationService $sessionRevocation,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $request->hasSession()) {
            return $next($request);
        }

        $session = $request->session();
        $identity = $this->identitySession->current($session);

        if ($identity !== null && $this->sessionRevocation->isRevoked($identity)) {
            $guard = $this->auth->guard();

            if ($guard instanceof StatefulGuard) {
                $guard->logout();
            }

            $session->invalidate();
            $session->regenerateToken();
        }

        return $next($request);
    }
}
