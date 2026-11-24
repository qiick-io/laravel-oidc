<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Support\Str;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Data\LogoutTokenData;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Exceptions\OidcNotConfiguredException;
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

        // Replay (BCL §2.6 step 8) is refused by the unique (issuer, jti) key
        // when the revocation is stored (M10); no cache pre-check could add
        // anything to that answer.
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

        // Eloquent returns '' for a missing token; other user models may return null.
        if ($user === null || (string) $user->getRememberToken() === '') {
            return;
        }

        $user->setRememberToken(Str::random(60));
        $user->timestamps = false;
        $user->save();
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function optionalString(array $claims, string $name): ?string
    {
        $value = $claims[$name] ?? null;

        if (! is_string($value) || $value === '') {
            return null;
        }

        // The revocation table keeps `sub`, `sid` and `jti` in 255-character
        // columns (OIDC Core 2 caps `sub` there too); MySQL would truncate a
        // longer value or refuse the row.
        if (strlen($value) > 255) {
            throw new InvalidTokenException("logout_token [{$name}] is longer than 255 characters.");
        }

        return $value;
    }
}
