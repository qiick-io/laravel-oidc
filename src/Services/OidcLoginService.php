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
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use LogicException;
use Qiick\Oidc\Contracts\SecondFactorChallengeContract;
use Qiick\Oidc\Contracts\UserClaimSynchronizationContract;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Enums\LoginRefusalReasonEnum;
use Qiick\Oidc\Events\OidcLoginSucceededEvent;
use Qiick\Oidc\Exceptions\LoginRefusedException;
use Qiick\Oidc\Models\UserIdentity;
use Symfony\Component\HttpFoundation\Response;

/**
 * Turns a validated SSO identity into a local login:
 * 1. resolve the local user (linking, auto-link, JIT);
 * 2. record authentication metadata, map roles, sync claims and decide
 *    whether this user needs a local challenge. A refusal rolls back JIT;
 * 3. hand over to a pending challenge or log in, regenerate the session ID,
 *    keep the identity for logout and announce it.
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
        $challenge = null;
        $hasPreparedLogin = false;
        $linkedIdentity = $this->userLinking->resolve($identity, function (UserIdentity $linkedIdentity, Model&Authenticatable $user) use ($request, $identity, &$challenge, &$hasPreparedLogin): void {
            $challenge = $this->prepareLogin($request, $linkedIdentity, $user, $identity);
            $hasPreparedLogin = true;
        });
        $user = $linkedIdentity->user ?? throw new LogicException('A resolved identity always has its user.');

        if (! $hasPreparedLogin) {
            $challenge = $this->prepareLogin($request, $linkedIdentity, $user, $identity);
        }

        if ($challenge !== null) {
            $this->identitySession->rememberPending($request->session(), $identity, $this->userKey($user));

            return $challenge;
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

    /**
     * Local MFA policy can depend on this login's roles and profile claims.
     * For JIT users these writes run inside the provisioning transaction.
     *
     * @throws LoginRefusedException
     */
    private function prepareLogin(
        Request $request,
        UserIdentity $linkedIdentity,
        Model&Authenticatable $user,
        AuthenticatedIdentityData $identity,
    ): ?Response {
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

        if (! $this->secondFactorChallenge->isRequired($user) || $this->multiFactorClaims->isSatisfied($identity)) {
            return null;
        }

        $challenge = $this->secondFactorChallenge->challenge($request, $user, $this->shouldRemember);

        if ($challenge === null) {
            $reason = LoginRefusalReasonEnum::SecondFactorUnavailable;
            Log::warning('OIDC login refused because the required second-factor challenge is unavailable.', [
                'reason' => $reason->value,
                'request_id' => (string) Str::uuid(),
            ]);

            throw new LoginRefusedException($reason);
        }

        return $challenge;
    }

    private function userKey(Model $user): int|string
    {
        $key = $user->getKey();

        return is_int($key) || is_string($key) ? $key : throw new LogicException('The user key must be an int or a string.');
    }
}
