<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
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
    private const array KEY_TYPES_BY_ALGORITHM_PREFIX = ['RS' => 'RSA', 'PS' => 'RSA', 'ES' => 'EC'];

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
        $cacheKey = 'oidc:jwks:'.hash('sha256', $discovery->jwksUri);
        $cachedKeys = $this->cache->get($cacheKey);
        $publishedKeys = is_array($cachedKeys) ? $cachedKeys : $this->fetchAndCache($discovery, $cacheKey);
        $matchingKey = $this->findKey($publishedKeys, $keyId, $algorithm);

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

        return $parsedKey;
    }

    /**
     * @return list<array<string, mixed>>
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

        /** @var list<array<string, mixed>> $validKeys */
        $validKeys = array_values(array_filter($publishedKeys, is_array(...)));

        $this->cache->put($cacheKey, $validKeys, $this->cacheSeconds);

        return $validKeys;
    }

    /**
     * Picks the signing key for the token. Encryption keys (`use: enc`), keys
     * of the wrong type and keys pinned to another `alg` are skipped. A token
     * without `kid` is accepted only when exactly one candidate is left.
     *
     * @param  array<array-key, mixed>  $publishedKeys
     * @return array<string, mixed>|null
     */
    private function findKey(array $publishedKeys, ?string $keyId, string $algorithm): ?array
    {
        $expectedKeyType = self::KEY_TYPES_BY_ALGORITHM_PREFIX[substr($algorithm, 0, 2)] ?? null;
        $candidates = [];

        foreach ($publishedKeys as $publishedKey) {
            if (! is_array($publishedKey)) {
                continue;
            }

            $isSigningKey = ($publishedKey['use'] ?? 'sig') === 'sig';
            $hasExpectedType = ($publishedKey['kty'] ?? null) === $expectedKeyType;
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

        return $candidates[0] ?? null;
    }

    /**
     * True at most once per cooldown window for a given JWKS.
     */
    private function mayRefetch(string $cacheKey): bool
    {
        return $this->cache->add($cacheKey.':refetch', true, $this->refetchCooldownSeconds);
    }
}
