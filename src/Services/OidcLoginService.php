<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Date;
use LogicException;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Events\OidcLoginSucceededEvent;
use Qiick\Oidc\Exceptions\LoginRefusedException;

/**
 * Turns a validated SSO identity into a local login: resolve the user, log in
 * on the default guard, regenerate the session id (session fixation), keep
 * the identity in the session for logout, then announce the login.
 *
 * Remember-me is off unless `oidc.remember` is on: a remember cookie would
 * outlive the IdP session and a back-channel logout.
 */
final readonly class OidcLoginService
{
    public function __construct(
        private UserLinkingService $userLinking,
        private IdentitySessionService $identitySession,
        private AuthFactory $auth,
        private Dispatcher $events,
        private bool $shouldRemember,
    ) {}

    /**
     * @throws LoginRefusedException when no local user may sign in with this identity
     */
    public function login(Request $request, AuthenticatedIdentityData $identity): Model&Authenticatable
    {
        $linkedIdentity = $this->userLinking->resolve($identity);
        $user = $linkedIdentity->user ?? throw new LogicException('A resolved identity always has its user.');

        $linkedIdentity->forceFill(['last_login_at' => Date::now()])->save();

        $guard = $this->auth->guard();

        if (! $guard instanceof StatefulGuard) {
            throw new LogicException('SSO login needs a stateful (session) guard as the default guard.');
        }

        $guard->login($user, $this->shouldRemember);

        $session = $request->session();
        $session->regenerate();
        $this->identitySession->remember($session, $identity);

        $this->events->dispatch(new OidcLoginSucceededEvent($user, $identity));

        return $user;
    }
}
