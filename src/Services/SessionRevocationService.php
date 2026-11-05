<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Date;
use Qiick\Oidc\Data\IdentitySessionData;
use Qiick\Oidc\Data\LogoutTokenData;

/**
 * Remembers back-channel logouts until every local session they concern has
 * expired, and answers whether a local session was logged out.
 *
 * A back-channel logout arrives as a server-to-server call without the user's
 * cookie, so the app cannot end the session directly, and not every session
 * driver can destroy a session by id (the cookie driver cannot). Instead the
 * logout is recorded here and EnsureOidcSessionIsActiveMiddleware ends the
 * session on its next request:
 * - with `sid`, only the local sessions created by that IdP session;
 * - with `sub` alone, every local session of the user created before the
 *   logout.
 *
 * The cache store must be shared by every app server.
 */
final readonly class SessionRevocationService
{
    public function __construct(
        private CacheRepository $cache,
        private int $revocationSeconds,
    ) {}

    public function revoke(LogoutTokenData $logoutToken): void
    {
        if ($logoutToken->sessionId !== null) {
            $this->cache->put($this->sessionKey($logoutToken->issuer, $logoutToken->sessionId), true, $this->revocationSeconds);

            return;
        }

        if ($logoutToken->subject !== null) {
            $this->cache->put($this->subjectKey($logoutToken->issuer, $logoutToken->subject), Date::now()->getTimestamp(), $this->revocationSeconds);
        }
    }

    public function isRevoked(IdentitySessionData $identity): bool
    {
        if ($identity->sessionId !== null && $this->cache->has($this->sessionKey($identity->issuer, $identity->sessionId))) {
            return true;
        }

        $subjectRevokedAt = $this->cache->get($this->subjectKey($identity->issuer, $identity->subject));

        return is_int($subjectRevokedAt) && $identity->authenticatedAt <= $subjectRevokedAt;
    }

    private function sessionKey(string $issuer, string $sessionId): string
    {
        return 'oidc:revoked-sid:'.hash('sha256', $issuer.'|'.$sessionId);
    }

    private function subjectKey(string $issuer, string $subject): string
    {
        return 'oidc:revoked-sub:'.hash('sha256', $issuer.'|'.$subject);
    }
}
