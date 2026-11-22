<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Date;
use LogicException;
use Qiick\Oidc\Contracts\SecondFactorChallengeContract;
use Qiick\Oidc\Contracts\UserClaimSynchronizationContract;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Events\OidcLoginSucceededEvent;
use Qiick\Oidc\Exceptions\LoginRefusedException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Turns a validated SSO identity into a local login:
 * 1. resolve the local user (linking, auto-link, JIT);
 * 2. record last-login auth metadata from the validated id_token (M2);
 * 3. apply the role mapping, so the first request already has the IdP roles;
 * 4. optionally synchronise profile claims (S9; no-op by default);
 * 5. when the app requires 2FA and the IdP did not prove MFA (`amr` / `acr`),
 *    hand over to the app's own second factor instead of signing in;
 * 6. otherwise log in on the default guard, regenerate the session id
 *    (session fixation), keep the identity for logout and announce it.
 *
 * Remember-me is off unless `oidc.remember` is on: a remember cookie would
 * outlive the IdP session and a back-channel logout.
 */
final readonly class OidcLoginService
{
    public function __construct(
        private UserLinkingService $userLinking,
        private RoleMappingService $roleMapping,
        private UserClaimSynchronizationContract $userClaimSynchronization,
        private MultiFactorClaimService $multiFactorClaims,
        private SecondFactorChallengeContract $secondFactorChallenge,
        private IdentitySessionService $identitySession,
        private AuthFactory $auth,
        private Dispatcher $events,
        private bool $shouldRemember,
    ) {}

    /**
     * @return Response|null the app's second-factor challenge to send the browser to,
     *                       or null when the user is now signed in
     *
     * @throws LoginRefusedException when no local user may sign in with this identity
     */
    public function login(Request $request, AuthenticatedIdentityData $identity): ?Response
    {
        $linkedIdentity = $this->userLinking->resolve($identity);
        $user = $linkedIdentity->user ?? throw new LogicException('A resolved identity always has its user.');

        $authenticationTime = $identity->authTime();

        $linkedIdentity->forceFill([
            'last_login_at' => Date::now(),
            'last_auth_time_at' => $authenticationTime !== null ? Date::createFromTimestamp($authenticationTime) : null,
            'last_acr' => $identity->acr(),
            'last_amr' => $identity->amr(),
            'last_id_token_alg' => $identity->idTokenAlgorithm(),
        ])->save();

        $this->roleMapping->apply($user, $identity);
        $this->userClaimSynchronization->synchronize($user, $identity);

        if ($this->secondFactorChallenge->isRequired($user) && ! $this->multiFactorClaims->isSatisfied($identity)) {
            $challenge = $this->secondFactorChallenge->challenge($request, $user, $this->shouldRemember);

            if ($challenge !== null) {
                $this->identitySession->rememberPending($request->session(), $identity, $this->userKey($user));

                return $challenge;
            }
        }

        $guard = $this->auth->guard();

        if (! $guard instanceof StatefulGuard) {
            throw new LogicException('SSO login needs a stateful (session) guard as the default guard.');
        }

        $guard->login($user, $this->shouldRemember);

        $session = $request->session();
        $session->regenerate();
        $this->identitySession->remember($session, $identity);

        $this->events->dispatch(new OidcLoginSucceededEvent($user, $identity));

        return null;
    }

    private function userKey(Model $user): int|string
    {
        $key = $user->getKey();

        return is_int($key) || is_string($key) ? $key : throw new LogicException('The user key must be an int or a string.');
    }
}
