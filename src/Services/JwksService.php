<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Date;
use OpenSSLAsymmetricKey;
use Qiick\Oidc\Data\DiscoveryDocumentData;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Throwable;

/**
 * Finds the public key that signed a JWT in the IdP's JWKS.
 *
 * The key set is cached. A token whose `kid` is not in the cached set makes
 * the service refetch the set once, because the IdP may have rotated its keys
 * (OIDC Core 10.1.1). Refetches are rate limited by a cooldown, so tokens with
 * random `kid` values (for example on the public back-channel logout endpoint)
 * cannot make the app hammer the IdP.
 */
final readonly class JwksService
{
    public function __construct(
        private IdentityProviderHttpService $identityProviderHttp,
        private CacheRepository $cache,
        private int $cacheSeconds,
        private int $refetchCooldownSeconds,
    ) {}

    /**
     * @throws InvalidTokenException when no usable key matches
     * @throws IdentityProviderRequestException when the JWKS cannot be fetched
     */
    public function key(DiscoveryDocumentData $discovery, ?string $keyId, string $algorithm): Key
    {
        $cacheKey = sprintf('oidc:jwks:%s', hash('sha256', $discovery->jwksUri));
        $cachedKeys = $this->cache->get($cacheKey);
        $publishedKeys = is_array($cachedKeys) ? $cachedKeys : $this->fetchAndCache($discovery, $cacheKey);

        try {
            $matchingKey = $this->findKey($publishedKeys, $keyId, $algorithm);
        } catch (InvalidTokenException $ambiguousKeyId) {
            // A cached set with the kid twice must not block logins until the
            // cache expires once the IdP fixes it: refetch, within the cooldown.
            if (! is_array($cachedKeys) || ! $this->mayRefetch($cacheKey)) {
                throw $ambiguousKeyId;
            }

            $matchingKey = $this->findKey($this->fetchAndCache($discovery, $cacheKey), $keyId, $algorithm);
        }

        if ($matchingKey === null && is_array($cachedKeys) && $this->mayRefetch($cacheKey)) {
            $matchingKey = $this->findKey($this->fetchAndCache($discovery, $cacheKey), $keyId, $algorithm);
        }

        if ($matchingKey === null) {
            throw new InvalidTokenException('No signing key in the JWKS matches the token (kid or algorithm).');
        }

        try {
            $parsedKey = JWK::parseKey($matchingKey, $algorithm);
        } catch (Throwable) {
            throw new InvalidTokenException('The matching JWKS key cannot be parsed.');
        }

        if ($parsedKey === null) {
            throw new InvalidTokenException('The matching JWKS key uses an unsupported curve.');
        }

        $this->assertRsaKeyIsLongEnough($parsedKey);

        return $parsedKey;
    }

    /**
     * RSA keys need at least 2048 bits (RFC 7518 §3.3 and §3.5). php-jwt
     * checks it for RS* but not for PS256, so the package checks every RSA
     * key itself.
     *
     * @throws InvalidTokenException
     */
    private function assertRsaKeyIsLongEnough(Key $parsedKey): void
    {
        $keyMaterial = $parsedKey->getKeyMaterial();
        $keyDetails = $keyMaterial instanceof OpenSSLAsymmetricKey ? openssl_pkey_get_details($keyMaterial) : false;

        if (is_array($keyDetails) && $keyDetails['type'] === OPENSSL_KEYTYPE_RSA && $keyDetails['bits'] < 2048) {
            throw new InvalidTokenException('The matching JWKS key is an RSA key shorter than 2048 bits.');
        }
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws IdentityProviderRequestException
     */
    private function fetchAndCache(DiscoveryDocumentData $discovery, string $cacheKey): array
    {
        $keySet = $this->identityProviderHttp->getJson($discovery->jwksUri);
        $publishedKeys = $keySet['keys'] ?? null;

        if (! is_array($publishedKeys)) {
            throw new IdentityProviderRequestException('The JWKS has no [keys] array.');
        }

        // Cached as published: findKey() skips any entry that is not a key object.
        $this->cache->put($cacheKey, $publishedKeys, $this->cacheSeconds);

        return $publishedKeys;
    }

    /**
     * Picks the signing key for the token. Skipped: encryption keys (`use:
     * enc`), keys whose `key_ops` lacks `verify` (RFC 7517 §4.3), keys of the
     * wrong type, EC keys on another curve than the algorithm's (RFC 7518
     * §3.4) and keys pinned to another `alg`. A token without `kid` is
     * accepted only when exactly one candidate is left; a `kid` that names
     * several candidates is ambiguous and refused (fail closed).
     *
     * @param  array<array-key, mixed>  $publishedKeys
     * @return array<string, mixed>|null
     *
     * @throws InvalidTokenException when the token's kid names several keys
     */
    private function findKey(array $publishedKeys, ?string $keyId, string $algorithm): ?array
    {
        $expectedKeyType = match (substr($algorithm, 0, 2)) {
            'RS', 'PS' => 'RSA',
            'ES' => 'EC',
            default => null,
        };
        $candidates = [];

        foreach ($publishedKeys as $publishedKey) {
            if (! is_array($publishedKey)) {
                continue;
            }

            $keyOperations = $publishedKey['key_ops'] ?? ['verify'];
            $isSigningKey = ($publishedKey['use'] ?? 'sig') === 'sig' && is_array($keyOperations) && in_array('verify', $keyOperations, true);
            $hasExpectedType = ($publishedKey['kty'] ?? null) === $expectedKeyType && $this->hasCurveOf($publishedKey, $algorithm);
            $hasCompatibleAlgorithm = ! isset($publishedKey['alg']) || $publishedKey['alg'] === $algorithm;
            $hasMatchingKeyId = $keyId === null || ($publishedKey['kid'] ?? null) === $keyId;

            if ($isSigningKey && $hasExpectedType && $hasCompatibleAlgorithm && $hasMatchingKeyId) {
                /** @var array<string, mixed> $publishedKey */
                $candidates[] = $publishedKey;
            }
        }

        if ($keyId === null && count($candidates) !== 1) {
            return null;
        }

        if (count($candidates) > 1) {
            throw new InvalidTokenException("The JWKS publishes the kid [{$keyId}] more than once.");
        }

        return $candidates[0] ?? null;
    }

    /**
     * ES256 is defined on P-256 and ES384 on P-384 only (RFC 7518 §3.4);
     * other algorithms carry no curve.
     *
     * @param  array<array-key, mixed>  $publishedKey
     */
    private function hasCurveOf(array $publishedKey, string $algorithm): bool
    {
        $expectedCurve = match ($algorithm) {
            'ES256' => 'P-256',
            'ES384' => 'P-384',
            default => null,
        };

        return $expectedCurve === null || ($publishedKey['crv'] ?? null) === $expectedCurve;
    }

    /**
     * True at most once per cooldown window for a given JWKS.
     */
    private function mayRefetch(string $cacheKey): bool
    {
        return $this->cache->add("{$cacheKey}:refetch", Date::now()->getTimestamp(), $this->refetchCooldownSeconds);
    }
}
