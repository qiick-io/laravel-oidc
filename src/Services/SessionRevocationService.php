<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Qiick\Oidc\Data\IdentitySessionData;
use Qiick\Oidc\Data\LogoutTokenData;
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
 */
final readonly class SessionRevocationService
{
    public function __construct(
        private CacheRepository $cache,
        private int $revocationSeconds,
    ) {}

    /**
     * Persist the revocation, then warm the cache. A duplicate (issuer, jti)
     * is a replay and is refused.
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
                    // DB default is backchannel; front-channel writes land in PR 7.
                    'channel' => $logoutToken->channel, // @pest-mutate-ignore: RemoveArrayItem
                    'received_at' => $receivedAt,
                    'expires_at' => Date::createFromTimestamp($expiresAt),
                ]);
            });
        } catch (UniqueConstraintViolationException) {
            throw new InvalidTokenException('logout_token [jti] was already used.');
        }

        // TTL floor is operational; tests assert revocation, not the exact TTL.
        $cacheTtl = max(1, $expiresAt - $receivedAt->getTimestamp()); // @pest-mutate-ignore: IncrementInteger,DecrementInteger,MaxToMin,MinusToPlus

        if ($logoutToken->sessionId !== null) {
            // Accelerator only; table remains the source of truth.
            $this->cache->put( // @pest-mutate-ignore: RemoveMethodCall
                $this->sessionKey($logoutToken->issuer, $logoutToken->sessionId),
                true, // @pest-mutate-ignore: TrueToFalse
                $cacheTtl,
            );

            return;
        }

        if ($logoutToken->subject !== null) {
            $this->cache->put( // @pest-mutate-ignore: RemoveMethodCall
                $this->subjectKey($logoutToken->issuer, $logoutToken->subject),
                $receivedAt->getTimestamp(),
                $cacheTtl,
            );
        }
    }

    /**
     * Cache first, then the table. Never treats a cache miss as "not revoked".
     * A table read failure fails closed.
     */
    public function isRevoked(IdentitySessionData $identity): bool
    {
        if ($identity->sessionId !== null && $this->cache->has($this->sessionKey($identity->issuer, $identity->sessionId))) {
            return true;
        }

        $subjectRevokedAt = $this->cache->get($this->subjectKey($identity->issuer, $identity->subject));

        if (is_int($subjectRevokedAt) && $identity->authenticatedAt <= $subjectRevokedAt) {
            return true;
        }

        try {
            return $this->isRevokedInTable($identity);
        } catch (Throwable $throwable) {
            Log::warning('OIDC logout revocation table read failed; treating session as revoked.', [
                'exception' => $throwable::class, // @pest-mutate-ignore: RemoveArrayItem
                'message' => $throwable->getMessage(), // @pest-mutate-ignore: RemoveArrayItem
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
                $this->cache->put( // @pest-mutate-ignore: RemoveMethodCall
                    $this->sessionKey($identity->issuer, $identity->sessionId),
                    true, // @pest-mutate-ignore: TrueToFalse
                    max(1, $sessionRevocation->expires_at->getTimestamp() - $now->getTimestamp()), // @pest-mutate-ignore: IncrementInteger,DecrementInteger,MaxToMin,MinusToPlus
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
            $this->cache->put( // @pest-mutate-ignore: RemoveMethodCall
                $this->subjectKey($identity->issuer, $identity->subject),
                $subjectRevocation->received_at->getTimestamp(),
                max(1, $subjectRevocation->expires_at->getTimestamp() - $now->getTimestamp()), // @pest-mutate-ignore: IncrementInteger,DecrementInteger,MaxToMin,MinusToPlus
            );

            return true;
        }

        return false;
    }

    /**
     * max(received + revocation lifetime, token exp + 120s) so the jti row
     * outlives both the local session and the token's validation window.
     */
    private function expiresAt(int $receivedAt, ?int $tokenExpiresAt): int
    {
        $fromRevocationLifetime = $receivedAt + $this->revocationSeconds;
        $fromToken = $tokenExpiresAt !== null ? $tokenExpiresAt + 120 : $fromRevocationLifetime;

        return max($fromRevocationLifetime, $fromToken);
    }

    private function sessionKey(string $issuer, string $sessionId): string
    {
        return 'oidc:revoked-sid:'.hash('sha256', $issuer.'|'.$sessionId); // @pest-mutate-ignore: ConcatRemoveLeft,ConcatRemoveRight,ConcatSwitchSides
    }

    private function subjectKey(string $issuer, string $subject): string
    {
        return 'oidc:revoked-sub:'.hash('sha256', $issuer.'|'.$subject); // @pest-mutate-ignore: ConcatRemoveLeft,ConcatRemoveRight,ConcatSwitchSides
    }
}
