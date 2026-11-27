<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Qiick\Oidc\Data\IdentitySessionData;
use Qiick\Oidc\Data\LogoutTokenData;
use Qiick\Oidc\Events\OidcLogoutReceivedEvent;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Models\OidcLogoutRevocation;
use Throwable;

/**
 * Remembers OIDC logouts until every local session they concern has expired,
 * and answers whether a local session was logged out.
 *
 * Source of truth is `oidc_logout_revocations` (standards review M10). The
 * cache is only an accelerator: a miss never means "not revoked", and a
 * failed table read fails closed (treated as revoked). Unique (issuer, jti)
 * is the durable BCL §2.6 replay check.
 *
 * @internal Not part of the public API (docs/public-api.md); it can change in any release.
 */
final readonly class SessionRevocationService
{
    public function __construct(
        private CacheRepository $cache,
        private int $revocationSeconds,
        private Dispatcher $events,
        private int $leewaySeconds,
    ) {}

    /**
     * Persist the revocation, then warm the cache. A duplicate (issuer, jti)
     * is a replay and is refused. Dispatches OidcLogoutReceivedEvent once the
     * row is committed and cached, so a listener never logs a logout that was
     * not stored.
     *
     * @throws InvalidTokenException when the logout token jti was already used
     */
    public function revoke(LogoutTokenData $logoutToken): void
    {
        $receivedAt = Date::now();
        $expiresAt = $this->expiresAt($receivedAt->getTimestamp(), $logoutToken->expiresAt);

        try {
            DB::transaction(function () use ($logoutToken, $receivedAt, $expiresAt): void {
                OidcLogoutRevocation::query()->create([
                    'issuer' => $logoutToken->issuer,
                    'sid' => $logoutToken->sessionId,
                    'sub' => $logoutToken->subject,
                    'jti' => $logoutToken->tokenId,
                    'replay_key' => $logoutToken->tokenId === null ? null : hash('sha256', $logoutToken->tokenId),
                    // Callers set backchannel or frontchannel; the DB default is backchannel.
                    'channel' => $logoutToken->channel,
                    'received_at' => $receivedAt,
                    'expires_at' => Date::createFromTimestamp($expiresAt),
                ]);
            });
        } catch (UniqueConstraintViolationException) {
            throw new InvalidTokenException('logout_token [jti] was already used.');
        }

        // Accelerator only; the table remains the source of truth.
        if ($logoutToken->sessionId !== null) {
            $this->warmCache(self::cacheKey('sid', $logoutToken->issuer, $logoutToken->sessionId), $receivedAt->getTimestamp(), $expiresAt);
        } elseif ($logoutToken->subject !== null) {
            $this->warmCache(self::cacheKey('sub', $logoutToken->issuer, $logoutToken->subject), $receivedAt->getTimestamp(), $expiresAt);
        }

        $this->dispatchLogoutReceived($logoutToken);
    }

    /**
     * Tells the app about a stored logout. The logout is already committed
     * and cached, so an app listener that throws must not turn it into an
     * error answer: the IdP would retry and hit the `jti` replay check, and
     * the caller would skip the rest of its work (the remember token). The
     * failure is logged instead, without the token or the sid.
     */
    private function dispatchLogoutReceived(LogoutTokenData $logoutToken): void
    {
        try {
            $this->events->dispatch(new OidcLogoutReceivedEvent(
                channel: $logoutToken->channel,
                issuer: $logoutToken->issuer,
                subject: $logoutToken->subject,
                sessionIdHash: $logoutToken->sessionId !== null ? hash('sha256', $logoutToken->sessionId) : null,
            ));
        } catch (Throwable $throwable) {
            Log::error('OidcLogoutReceivedEvent listener failed; the logout itself is stored.', [
                'exception' => $throwable::class,
            ]);
        }
    }

    /**
     * A cache miss falls through to the revocation table. A table read
     * failure fails closed.
     */
    public function isRevoked(IdentitySessionData $identity): bool
    {
        // App repositories can enable SSO at runtime without the boot-time config flag.
        if (! OidcLogoutRevocation::isSessionLifetimeCovered()) {
            return true;
        }

        if ($identity->sessionId !== null && $this->cache->has(self::cacheKey('sid', $identity->issuer, $identity->sessionId))) {
            return true;
        }

        $subjectRevokedAt = $this->cache->get(self::cacheKey('sub', $identity->issuer, $identity->subject));

        if (is_int($subjectRevokedAt) && $identity->authenticatedAt <= $subjectRevokedAt) {
            return true;
        }

        try {
            return $this->isRevokedInTable($identity);
        } catch (Throwable $throwable) {
            // Database exception messages can contain the subject and SID bindings.
            Log::warning('OIDC logout revocation table read failed; treating session as revoked.', [
                'exception' => $throwable::class,
            ]);

            return true;
        }
    }

    /**
     * Only the table may answer "not revoked".
     *
     * @throws Throwable when the database cannot be read
     */
    private function isRevokedInTable(IdentitySessionData $identity): bool
    {
        $now = Date::now();

        if ($identity->sessionId !== null) {
            $sessionRevocation = OidcLogoutRevocation::query()
                ->where('issuer', $identity->issuer)
                ->where('sid', $identity->sessionId)
                ->where('expires_at', '>', $now)
                ->orderByDesc('received_at')
                ->first();

            if ($sessionRevocation !== null) {
                $this->warmCache(
                    self::cacheKey('sid', $identity->issuer, $identity->sessionId),
                    $sessionRevocation->received_at->getTimestamp(),
                    $sessionRevocation->expires_at->getTimestamp(),
                );

                return true;
            }
        }

        $subjectRevocation = OidcLogoutRevocation::query()
            ->where('issuer', $identity->issuer)
            ->where('sub', $identity->subject)
            ->whereNull('sid')
            ->where('expires_at', '>', $now)
            ->where('received_at', '>=', Date::createFromTimestamp($identity->authenticatedAt))
            ->orderByDesc('received_at')
            ->first();

        if ($subjectRevocation !== null) {
            $this->warmCache(
                self::cacheKey('sub', $identity->issuer, $identity->subject),
                $subjectRevocation->received_at->getTimestamp(),
                $subjectRevocation->expires_at->getTimestamp(),
            );

            return true;
        }

        return false;
    }

    /**
     * Fixed at write time: max(received + configured revocation lifetime,
     * token exp + max(120 s, clock leeway)). The validator accepts a token
     * until exp + leeway, so the row, whose unique (issuer, jti) refuses a
     * replay, must outlive that. The configured lifetime is already the max
     * of `oidc.backchannel_logout.revocation_ttl` and `session.lifetime`;
     * prune deletes by this stored expires_at and never recomputes the TTL.
     */
    private function expiresAt(int $receivedAt, int|float|null $tokenExpiresAt): int
    {
        $latestExpiry = $receivedAt + OidcLogoutRevocation::maximumRetentionSeconds();
        $replayWindowSeconds = max(120, $this->leewaySeconds);

        // BCL §2.6 requires replay protection for as long as a token is accepted.
        // Refuse the token if its window cannot fit in the retention bound.
        if ($tokenExpiresAt !== null && $tokenExpiresAt > $latestExpiry - $replayWindowSeconds) {
            throw new InvalidTokenException('logout_token expiry exceeds oidc.backchannel_logout.max_retention_seconds.');
        }

        $fromRevocationLifetime = $receivedAt + $this->revocationSeconds;
        // JSON NumericDate values can be fractional (RFC 7519). Round up after
        // enforcing the upper bound so an oversized value cannot wrap as an int.
        $fromToken = $tokenExpiresAt !== null ? (int) ceil($tokenExpiresAt + $replayWindowSeconds) : $fromRevocationLifetime;

        return max($fromRevocationLifetime, $fromToken);
    }

    /**
     * Cache until the row's expiry or 24 hours, whichever comes first. A SID
     * can be unattributable during erasure, so a cache entry has a shorter
     * bound than the durable ledger. The stored value is the logout cut-off.
     */
    private function warmCache(string $cacheKey, int $receivedAt, int $expiresAt): void
    {
        $cacheExpiresAt = min($expiresAt, Date::now()->getTimestamp() + 86_400);
        $this->cache->put($cacheKey, $receivedAt, Date::createFromTimestamp($cacheExpiresAt));
    }

    /**
     * One key per issuer and `sid` or `sub`; `$kind` keeps a `sid` and a
     * `sub` with the same value apart.
     *
     * @param  'sid'|'sub'  $kind
     */
    public static function cacheKey(string $kind, string $issuer, string $value): string
    {
        return sprintf('oidc:revoked-%s:%s', $kind, hash('sha256', sprintf('%s|%s', $issuer, $value)));
    }
}
