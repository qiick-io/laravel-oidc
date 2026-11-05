<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Date;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Data\IdentitySessionData;

/**
 * Keeps the SSO identity of the current login in the Laravel session.
 *
 * Call remember() right after Auth::login() and the session regeneration, so
 * the identity lives in the new session id. Laravel copies session data on
 * regenerate() and drops it on invalidate(), which is the lifecycle wanted.
 */
final readonly class IdentitySessionService
{
    public const string SESSION_KEY = 'oidc.identity';

    public const string PENDING_SESSION_KEY = 'oidc.pending_identity';

    /**
     * How long an identity waits for the app's second factor, in seconds.
     */
    public const int PENDING_SECONDS = 600;

    public function remember(Session $session, AuthenticatedIdentityData $identity): void
    {
        $session->put(self::SESSION_KEY, $this->identitySession($identity)->toArray());
    }

    /**
     * Parks the identity while the app runs its own second factor. The
     * PromotePendingIdentityListener moves it to the session identity when
     * that user signs in, so logout and back-channel logout work after the
     * challenge too.
     */
    public function rememberPending(Session $session, AuthenticatedIdentityData $identity, int|string $userId): void
    {
        $session->put(self::PENDING_SESSION_KEY, [
            'user_id' => $userId,
            'expires_at' => Date::now()->getTimestamp() + self::PENDING_SECONDS,
            'identity' => $this->identitySession($identity)->toArray(),
        ]);
    }

    /**
     * Turns the pending identity into the session identity when the signed-in
     * user is the one who passed the SSO login. Any other login just drops it.
     */
    public function promotePending(Session $session, int|string $userId): void
    {
        $pending = $session->pull(self::PENDING_SESSION_KEY);

        $pendingUserId = is_array($pending) ? ($pending['user_id'] ?? null) : null;

        if (! is_array($pending)
            || (! is_int($pendingUserId) && ! is_string($pendingUserId))
            || (string) $pendingUserId !== (string) $userId
            || ! is_int($pending['expires_at'] ?? null)
            || $pending['expires_at'] < Date::now()->getTimestamp()) {
            return;
        }

        $identity = IdentitySessionData::fromArray($pending['identity'] ?? null);

        if ($identity !== null) {
            $session->put(self::SESSION_KEY, [...$identity->toArray(), 'authenticated_at' => Date::now()->getTimestamp()]);
        }
    }

    private function identitySession(AuthenticatedIdentityData $identity): IdentitySessionData
    {
        return new IdentitySessionData(
            issuer: $identity->issuer,
            subject: $identity->subject,
            sessionId: $identity->sessionId,
            idToken: $identity->idToken,
            authenticatedAt: Date::now()->getTimestamp(),
        );
    }

    /**
     * The identity of the current session, or null for a local login.
     */
    public function current(Session $session): ?IdentitySessionData
    {
        return IdentitySessionData::fromArray($session->get(self::SESSION_KEY));
    }

    public function forget(Session $session): void
    {
        $session->forget(self::SESSION_KEY);
    }
}
