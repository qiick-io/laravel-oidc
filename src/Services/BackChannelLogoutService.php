<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Str;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Data\LogoutTokenData;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Exceptions\OidcNotConfiguredException;
use Qiick\Oidc\Models\OidcLogoutRevocation;
use Qiick\Oidc\Models\UserIdentity;

/**
 * Handles a back-channel logout request (OpenID Connect Back-Channel Logout
 * 1.0): validates the `logout_token` and records the logout.
 *
 * Validation (section 2.6), on top of the shared JWT checks (signature, `iss`,
 * `aud`, `exp`, `iat`):
 * - `events` has the back-channel logout member, so an id_token or another
 *   JWT for this client cannot be replayed as a logout;
 * - `nonce` is absent, for the same reason;
 * - `sub`, `sid` or both are present;
 * - `jti` is present and seen only once while the token is valid.
 *
 * The endpoint is public and unauthenticated by design; the signature is the
 * authentication. The JWKS refetch cooldown keeps forged `kid` values from
 * turning it into an amplifier against the IdP.
 */
final readonly class BackChannelLogoutService
{
    public const string LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function __construct(
        private ProviderConfigurationRepositoryContract $configurationRepository,
        private DiscoveryService $discovery,
        private JwtValidatorService $jwtValidator,
        private SessionRevocationService $sessionRevocation,
        private CacheRepository $cache,
    ) {}

    /**
     * @throws InvalidTokenException when the logout_token is not acceptable
     * @throws IdentityProviderRequestException when discovery or the JWKS fails
     * @throws OidcNotConfiguredException
     */
    public function handle(#[\SensitiveParameter] string $logoutToken): LogoutTokenData
    {
        $configuration = $this->configurationRepository->configuration();
        $discovery = $this->discovery->discover($configuration);
        $claims = $this->jwtValidator->validate($logoutToken, $discovery, $configuration);

        $events = $claims['events'] ?? null;

        if (! is_array($events) || ! array_key_exists(self::LOGOUT_EVENT, $events) || ! is_array($events[self::LOGOUT_EVENT])) {
            throw new InvalidTokenException('logout_token has no back-channel logout event.');
        }

        if (array_key_exists('nonce', $claims)) {
            throw new InvalidTokenException('logout_token must not contain [nonce].');
        }

        $subject = $this->optionalString($claims, 'sub');
        $sessionId = $this->optionalString($claims, 'sid');

        if ($subject === null && $sessionId === null) {
            throw new InvalidTokenException('logout_token has neither [sub] nor [sid].');
        }

        // As for the id_token: an untrimmed `sub` compares equal to another identity's on the
        // MySQL family and would cycle that user's remember token.
        if ($subject !== null && trim($subject) !== $subject) {
            throw new InvalidTokenException('logout_token [sub] has leading or trailing whitespace.');
        }

        $tokenId = $this->optionalString($claims, 'jti');

        if ($tokenId === null) {
            throw new InvalidTokenException('logout_token has no [jti].');
        }

        // Accelerator only: never refuse on a cache-only hit. Durable replay
        // refusal is unique (issuer, jti) on insert (M10).
        $this->assertNotAlreadyUsed($discovery->issuer, $tokenId);

        $expiresAtClaim = $claims['exp'] ?? null;

        $logout = new LogoutTokenData(
            issuer: $discovery->issuer,
            subject: $subject,
            sessionId: $sessionId,
            tokenId: $tokenId,
            expiresAt: is_int($expiresAtClaim) ? $expiresAtClaim : null,
            channel: 'backchannel',
        );
        $this->sessionRevocation->revoke($logout);
        $this->rememberUsedTokenId($claims, $discovery->issuer, $tokenId);

        if ($subject !== null) {
            $this->cycleRememberToken($discovery->issuer, $subject);
        }

        return $logout;
    }

    /**
     * A remember-me cookie would log the user back in after the session ended,
     * and a new session carries no SSO identity to revoke. Cycling the linked
     * user's remember token makes every such cookie invalid. It only matters
     * when `oidc.remember` is on (or the user also signed in locally with
     * "remember me"); active sessions are handled by the revocation.
     */
    private function cycleRememberToken(string $issuer, string $subject): void
    {
        $user = UserIdentity::query()
            ->where('issuer', $issuer)
            ->where('subject', $subject)
            ->first()
            ?->user;

        if ($user === null || in_array($user->getRememberToken(), [null, ''], true)) {
            return;
        }

        $user->setRememberToken(Str::random(60));
        $user->timestamps = false;
        $user->save();
    }

    /**
     * Cache hit is never a terminal replay by itself: confirm a live table
     * row. A cache-only ghost (insert failed after a previous bug, or a
     * flushed/partial store) must not block the IdP's retry.
     *
     * @throws InvalidTokenException
     */
    private function assertNotAlreadyUsed(string $issuer, string $tokenId): void
    {
        if (! $this->cache->has($this->tokenIdCacheKey($issuer, $tokenId))) {
            return;
        }

        $hasLiveRow = OidcLogoutRevocation::query()
            ->where('issuer', $issuer)
            ->where('jti', $tokenId)
            ->where('expires_at', '>', Date::now())
            ->exists();

        if ($hasLiveRow) {
            throw new InvalidTokenException('logout_token [jti] was already used.');
        }
    }

    /**
     * Warm the jti accelerator only after the durable insert succeeded, so a
     * failed insert cannot poison the IdP's retry.
     *
     * @param  array<string, mixed>  $claims
     */
    private function rememberUsedTokenId(array $claims, string $issuer, string $tokenId): void
    {
        $expiresAt = $claims['exp'] ?? 0;
        $secondsUntilExpiry = (int) (is_int($expiresAt) || is_float($expiresAt) ? $expiresAt : 0) - Date::now()->getTimestamp();

        $this->cache->put(
            $this->tokenIdCacheKey($issuer, $tokenId),
            true,
            max(60, $secondsUntilExpiry + 120),
        );
    }

    private function tokenIdCacheKey(string $issuer, string $tokenId): string
    {
        return 'oidc:logout-jti:'.hash('sha256', $issuer.'|'.$tokenId);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function optionalString(array $claims, string $name): ?string
    {
        $value = $claims[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
