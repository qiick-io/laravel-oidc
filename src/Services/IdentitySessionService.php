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

    public function remember(Session $session, AuthenticatedIdentityData $identity): void
    {
        $session->put(self::SESSION_KEY, (new IdentitySessionData(
            issuer: $identity->issuer,
            subject: $identity->subject,
            sessionId: $identity->sessionId,
            idToken: $identity->idToken,
            authenticatedAt: Date::now()->getTimestamp(),
        ))->toArray());
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
