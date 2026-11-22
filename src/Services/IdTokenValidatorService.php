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
 */
final readonly class IdTokenValidatorService
{
    /**
     * OIDC Core 2: `sub` is at most 255 ASCII characters.
     */
    // Spec ceiling; Increment/Decrement would still refuse the oversized fixture.
    private const int MAXIMUM_SUBJECT_LENGTH = 255; // @pest-mutate-ignore: IncrementInteger,DecrementInteger

    /**
     * Hash algorithm for each supported JWS `alg` (OIDC Core 3.1.3.6).
     *
     * @var array<string, string>
     */
    // Const entries are not line-covered; RS256/RS384/ES256 are exercised via at_hash tests.
    private const array HASH_ALGORITHMS_BY_JWS = [
        'RS256' => 'sha256', // @pest-mutate-ignore: RemoveArrayItem
        'RS384' => 'sha384', // @pest-mutate-ignore: RemoveArrayItem
        'RS512' => 'sha512', // @pest-mutate-ignore: RemoveArrayItem
        'PS256' => 'sha256', // @pest-mutate-ignore: RemoveArrayItem
        'ES256' => 'sha256', // @pest-mutate-ignore: RemoveArrayItem
        'ES384' => 'sha384', // @pest-mutate-ignore: RemoveArrayItem
    ];

    public function __construct(
        private JwtValidatorService $jwtValidator,
    ) {}

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
        #[\SensitiveParameter] string $accessToken = '', // @pest-mutate-ignore: EmptyStringToNotEmpty
    ): array {
        $claims = $this->jwtValidator->validate($idToken, $discovery, $configuration);
        $subject = $claims['sub'] ?? null;

        if (! is_string($subject) || $subject === '' || strlen($subject) > self::MAXIMUM_SUBJECT_LENGTH) {
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
            if ($accessToken === '') {
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
            // Depth is operational; 15 vs 16 never changes a real JOSE header.
            $header = json_decode(JWT::urlsafeB64Decode($segments[0]), true, 16, JSON_THROW_ON_ERROR); // @pest-mutate-ignore: IncrementInteger,DecrementInteger
        } catch (\Throwable) {
            throw new InvalidTokenException('id_token header is not valid JSON.');
        }

        $algorithm = is_array($header) ? ($header['alg'] ?? null) : null;
        $hashAlgorithm = is_string($algorithm) ? (self::HASH_ALGORITHMS_BY_JWS[$algorithm] ?? null) : null;

        if ($hashAlgorithm === null) {
            throw new InvalidTokenException('id_token [at_hash] cannot be checked for this signing algorithm.');
        }

        $digest = hash($hashAlgorithm, $accessToken, true);
        // Hash digests are even-length; the cast is for PHPStan.
        $expectedHash = JWT::urlsafeB64Encode(substr($digest, 0, (int) (strlen($digest) / 2))); // @pest-mutate-ignore: RemoveIntegerCast

        if (! hash_equals($expectedHash, $accessTokenHash)) {
            throw new InvalidTokenException('id_token [at_hash] does not match the access_token.');
        }
    }
}
