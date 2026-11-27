<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Firebase\JWT\JWT;
use Qiick\Oidc\Data\DiscoveryDocumentData;
use Qiick\Oidc\Data\ProviderConfigurationData;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Exceptions\InvalidTokenException;

/**
 * Validates the `id_token` of the token response (OIDC Core 3.1.3.7): the
 * shared JWT checks, plus a non-empty, trimmed `sub` and the `nonce` this
 * login sent.
 *
 * When `at_hash` is present it is checked against the access token (OIDC Core
 * 3.1.3.8 / 3.2.2.9; standards review S1). Absent `at_hash` is allowed in the
 * code flow.
 *
 * The nonce binds the token to the browser session that started the login,
 * so a token captured elsewhere cannot be replayed into another session.
 *
 * @internal Not part of the public API (docs/public-api.md); it can change in any release.
 */
final readonly class IdTokenValidatorService
{
    public function __construct(
        private JwtValidatorService $jwtValidator,
    ) {}

    /**
     * Hash algorithm for the JWS `alg` (OIDC Core 3.1.3.6). Null when the
     * header omits `alg` or names one this package cannot hash for `at_hash`.
     */
    private function hashAlgorithmForJws(mixed $algorithm): ?string
    {
        if (! is_string($algorithm)) {
            return null;
        }

        return match ($algorithm) {
            'RS256', 'PS256', 'ES256' => 'sha256',
            'RS384', 'ES384' => 'sha384',
            'RS512' => 'sha512',
            default => null,
        };
    }

    /**
     * @return array{sub: string, ...} the verified claims
     *
     * @throws InvalidTokenException
     * @throws IdentityProviderRequestException when the JWKS cannot be fetched
     */
    public function validate(
        #[\SensitiveParameter] string $idToken,
        DiscoveryDocumentData $discovery,
        ProviderConfigurationData $configuration,
        #[\SensitiveParameter] string $expectedNonce,
        #[\SensitiveParameter] ?string $accessToken = null,
    ): array {
        $claims = $this->jwtValidator->validate($idToken, $discovery, $configuration);
        $subject = $claims['sub'] ?? null;

        // OIDC Core 2: `sub` is at most 255 ASCII characters.
        if (! is_string($subject) || $subject === '' || strlen($subject) > 255) {
            throw new InvalidTokenException('id_token has no valid [sub].');
        }

        // OIDC Core 2 makes `sub` opaque, so no IdP needs surrounding whitespace in it, and the
        // MySQL family's PAD SPACE collations compare `sub ` equal to `sub`: such a `sub` would
        // sign in as another user's identity. The callback logs the refusal.
        if (trim($subject) !== $subject) {
            throw new InvalidTokenException('id_token [sub] has leading or trailing whitespace.');
        }

        $claims['sub'] = $subject;
        $nonce = $claims['nonce'] ?? null;

        if (! is_string($nonce) || ! hash_equals($expectedNonce, $nonce)) {
            throw new InvalidTokenException('id_token [nonce] does not match this login.');
        }

        if (array_key_exists('at_hash', $claims)) {
            if ($accessToken === null || $accessToken === '') {
                throw new InvalidTokenException('id_token [at_hash] is present but no access_token was issued.');
            }

            $this->assertAccessTokenHash($idToken, $accessToken, $claims['at_hash']);
        }

        return $claims;
    }

    /**
     * OIDC Core 3.2.2.9: left half of the access-token hash for the JWS alg,
     * base64url-encoded without padding.
     *
     * @throws InvalidTokenException
     */
    private function assertAccessTokenHash(
        #[\SensitiveParameter] string $idToken,
        #[\SensitiveParameter] string $accessToken,
        mixed $accessTokenHash,
    ): void {
        if (! is_string($accessTokenHash) || $accessTokenHash === '') {
            throw new InvalidTokenException('id_token [at_hash] is malformed.');
        }

        $segments = explode('.', $idToken);

        if (count($segments) !== 3) {
            throw new InvalidTokenException('id_token is not a signed JWT (JWS compact serialization).');
        }

        try {
            // JwtValidatorService already read this header with a depth limit.
            $header = json_decode(JWT::urlsafeB64Decode($segments[0]), true, flags: JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            throw new InvalidTokenException('id_token header is not valid JSON.');
        }

        $algorithm = is_array($header) ? ($header['alg'] ?? null) : null;
        $hashAlgorithm = $this->hashAlgorithmForJws($algorithm);

        if ($hashAlgorithm === null) {
            throw new InvalidTokenException('id_token [at_hash] cannot be checked for this signing algorithm.');
        }

        $digest = hash($hashAlgorithm, $accessToken, true);
        $expectedHash = JWT::urlsafeB64Encode(substr($digest, 0, intdiv(strlen($digest), 2)));

        if (! hash_equals($expectedHash, $accessTokenHash)) {
            throw new InvalidTokenException('id_token [at_hash] does not match the access_token.');
        }
    }
}
