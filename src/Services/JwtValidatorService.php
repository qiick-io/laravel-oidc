<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Support\Facades\Date;
use JsonException;
use phpseclib3\Crypt\RSA;
use Qiick\Oidc\Data\DiscoveryDocumentData;
use Qiick\Oidc\Data\ProviderConfigurationData;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use ReflectionProperty;
use Throwable;

/**
 * Validates a signed JWT issued by the IdP for this client: the checks the
 * `id_token` (OIDC Core 3.1.3.7) and the back-channel `logout_token`
 * (OIDC Back-Channel Logout 1.0, 2.6) have in common.
 *
 * - `alg` must be one of the configured asymmetric algorithms. `none` and the
 *   HMAC family are never accepted, so a token cannot be "signed" with the
 *   client secret or not at all.
 * - The signature is verified with the JWKS key named by `kid`.
 * - `iss` equals the discovered issuer, which equals the configured one.
 * - `aud` contains the client id, and any other audience is explicitly trusted;
 *   `azp`, when present or when there are several audiences, is the client id.
 * - `exp` and `iat` are required; `exp`, `iat` and `nbf` are checked with the
 *   configured leeway.
 *
 * Token-specific claims (`nonce`, `sub`, `events`, ...) are the caller's job.
 *
 * @internal Not part of the public API (docs/PUBLIC-API.md); it can change in any release.
 */
final readonly class JwtValidatorService
{
    /**
     * @param  list<string>  $allowedAlgorithms
     * @param  list<string>  $trustedAudiences  audiences besides the client id
     */
    public function __construct(
        private JwksService $jwks,
        private array $allowedAlgorithms,
        private int $leewaySeconds,
        private array $trustedAudiences,
    ) {}

    /**
     * Asymmetric algorithms the package can verify. The configured list is
     * intersected with this one, so a config typo cannot enable HS256.
     * A method rather than a constant, so the list is executed code that
     * mutation testing can check entry by entry.
     *
     * @return list<string>
     */
    public static function supportedAlgorithms(): array
    {
        return ['RS256', 'RS384', 'RS512', 'PS256', 'ES256', 'ES384'];
    }

    /**
     * @return array<string, mixed> the verified claims
     *
     * @throws InvalidTokenException when the token fails any check
     * @throws IdentityProviderRequestException when the JWKS cannot be fetched
     */
    public function validate(
        #[\SensitiveParameter] string $token,
        DiscoveryDocumentData $discovery,
        ProviderConfigurationData $configuration,
    ): array {
        $header = $this->decodeHeader($token);
        $algorithm = $header['alg'] ?? null;

        if (! is_string($algorithm) || ! in_array($algorithm, array_intersect(self::supportedAlgorithms(), $this->allowedAlgorithms), true)) {
            throw new InvalidTokenException('Token signing algorithm is not allowed.');
        }

        // RFC 7515 §4.1.11: a recipient must refuse a token whose `crit`
        // lists an extension it does not understand, and the package
        // understands none. An empty or malformed `crit` is invalid too.
        if (array_key_exists('crit', $header)) {
            throw new InvalidTokenException('Token header [crit] lists JWS extensions the package does not understand.');
        }

        $keyId = $header['kid'] ?? null;

        if ($keyId !== null && ! is_string($keyId)) {
            throw new InvalidTokenException('Token header [kid] is not a string.');
        }

        $claims = $this->verifySignatureAndTimes($token, $this->jwks->key($discovery, $keyId, $algorithm));

        if (($claims['iss'] ?? null) !== $discovery->issuer) {
            throw new InvalidTokenException('Token [iss] does not match the issuer.');
        }

        $this->assertAudience($claims, $configuration->clientId);
        $this->assertTimestamps($claims);

        return $claims;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws InvalidTokenException
     */
    private function decodeHeader(string $token): array
    {
        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            throw new InvalidTokenException('Token is not a signed JWT (JWS compact serialization).');
        }

        try {
            $header = json_decode(JWT::urlsafeB64Decode($segments[0]), true, 16, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw new InvalidTokenException('Token header is not valid JSON.');
        }

        if (! is_array($header)) {
            throw new InvalidTokenException('Token header is not a JSON object.');
        }

        /** @var array<string, mixed> $header */
        return $header;
    }

    /**
     * php-jwt reads the clock and the leeway from static properties. They are
     * set from Laravel's clock (so `Date::setTestNow()` works) and restored
     * afterwards, so other users of php-jwt in the app are not affected.
     *
     * @return array<string, mixed>
     *
     * @throws InvalidTokenException
     */
    private function verifySignatureAndTimes(string $token, Key $key): array
    {
        $previousTimestamp = JWT::$timestamp;
        $previousLeeway = JWT::$leeway;
        $previousSaltLengthDiscovery = (new ReflectionProperty(RSA::class, 'autoSaltLength'))->getValue();
        JWT::$timestamp = Date::now()->getTimestamp();
        JWT::$leeway = $this->leewaySeconds;
        // RFC 7518 §3.5: the PSS salt is as long as the hash. phpseclib, which
        // php-jwt uses for PS256, accepts any salt length unless told not to.
        RSA::disableSaltLengthDiscovery();

        try {
            $payload = JWT::decode($token, $key);
        } catch (ExpiredException) {
            throw new InvalidTokenException('Token has expired.');
        } catch (BeforeValidException) {
            throw new InvalidTokenException('Token is not valid yet (nbf or iat in the future).');
        } catch (SignatureInvalidException) {
            throw new InvalidTokenException('Token signature is invalid.');
        } catch (Throwable) {
            throw new InvalidTokenException('Token cannot be decoded or verified.');
        } finally {
            JWT::$timestamp = $previousTimestamp;
            JWT::$leeway = $previousLeeway;

            if ($previousSaltLengthDiscovery === true) {
                RSA::enableSaltLengthDiscovery();
            }
        }

        // OIDC Core §2: `aud` is a string or a JSON array. Checked on the
        // decoded JSON types, because an object such as {"0": "client"}
        // becomes a PHP list once decoded to arrays.
        if (isset($payload->aud) && ! is_string($payload->aud) && ! is_array($payload->aud)) {
            throw new InvalidTokenException('Token [aud] is missing or not a list of strings.');
        }

        try {
            $claims = json_decode(json_encode($payload, JSON_THROW_ON_ERROR), true);
        } catch (JsonException) {
            // A signed payload can still hold a number JSON cannot carry back,
            // such as `exp: 1e999` (INF): refuse it like any malformed token.
            throw new InvalidTokenException('Token payload cannot be represented as JSON.');
        }

        if (! is_array($claims)) {
            throw new InvalidTokenException('Token payload is not a JSON object.');
        }

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    /**
     * @param  array<string, mixed>  $claims
     *
     * @throws InvalidTokenException
     */
    private function assertAudience(array $claims, string $clientId): void
    {
        $audienceClaim = $claims['aud'] ?? null;
        $audiences = is_string($audienceClaim) ? [$audienceClaim] : (is_array($audienceClaim) ? $audienceClaim : []);

        // OIDC Core §2: `aud` is a string or a JSON array of strings. A JSON
        // object decodes to a keyed array, which array_is_list() refuses.
        if ($audiences === [] || ! array_is_list($audiences) || array_filter($audiences, is_string(...)) !== $audiences) {
            throw new InvalidTokenException('Token [aud] is missing or not a list of strings.');
        }

        /** @var list<string> $audiences */
        if (! in_array($clientId, $audiences, true)) {
            throw new InvalidTokenException('Token [aud] does not contain the client id.');
        }

        $untrustedAudiences = array_diff($audiences, [$clientId, ...$this->trustedAudiences]);

        if ($untrustedAudiences !== []) {
            throw new InvalidTokenException('Token [aud] contains an untrusted audience.');
        }

        $authorizedParty = $claims['azp'] ?? null;
        $hasSeveralAudiences = count($audiences) > 1;

        if (($authorizedParty !== null || $hasSeveralAudiences) && $authorizedParty !== $clientId) {
            throw new InvalidTokenException('Token [azp] is not the client id.');
        }
    }

    /**
     * php-jwt checks `exp` and `iat` only when present, and skips `iat` when
     * `nbf` is set. Both are required by OIDC, so they are checked here too.
     *
     * @param  array<string, mixed>  $claims
     *
     * @throws InvalidTokenException
     */
    private function assertTimestamps(array $claims): void
    {
        $now = Date::now()->getTimestamp();

        $expiresAt = $claims['exp'] ?? null;

        if (! is_int($expiresAt) && ! is_float($expiresAt)) {
            throw new InvalidTokenException('Token has no numeric [exp].');
        }

        $issuedAt = $claims['iat'] ?? null;

        if (! is_int($issuedAt) && ! is_float($issuedAt)) {
            throw new InvalidTokenException('Token has no numeric [iat].');
        }

        if ($issuedAt > $now + $this->leewaySeconds) {
            throw new InvalidTokenException('Token is not valid yet (nbf or iat in the future).');
        }
    }
}
