<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Date;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Data\LogoutTokenData;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Exceptions\OidcNotConfiguredException;

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

        $this->assertFirstUse($claims, $discovery->issuer);

        $logout = new LogoutTokenData($discovery->issuer, $subject, $sessionId);
        $this->sessionRevocation->revoke($logout);

        return $logout;
    }

    /**
     * @param  array<string, mixed>  $claims
     *
     * @throws InvalidTokenException
     */
    private function assertFirstUse(array $claims, string $issuer): void
    {
        $tokenId = $this->optionalString($claims, 'jti');

        if ($tokenId === null) {
            throw new InvalidTokenException('logout_token has no [jti].');
        }

        $expiresAt = $claims['exp'] ?? 0;
        $secondsUntilExpiry = (int) (is_int($expiresAt) || is_float($expiresAt) ? $expiresAt : 0) - Date::now()->getTimestamp();
        $isFirstUse = $this->cache->add('oidc:logout-jti:'.hash('sha256', $issuer.'|'.$tokenId), true, max(60, $secondsUntilExpiry + 120));

        if (! $isFirstUse) {
            throw new InvalidTokenException('logout_token [jti] was already used.');
        }
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
