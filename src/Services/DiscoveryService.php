<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Qiick\Oidc\Data\DiscoveryDocumentData;
use Qiick\Oidc\Data\ProviderConfigurationData;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Outbound\Ssrf\RemoteUrlGuard;
use Qiick\Outbound\Ssrf\UnsafeUrl;
use Qiick\Outbound\Ssrf\UrlGuardOptions;

/**
 * Fetches, validates and caches the OpenID Provider metadata of the issuer
 * (OIDC Discovery 1.0).
 *
 * Validation that matters for security:
 * - the document's `issuer` must equal the configured issuer exactly
 *   (Discovery 4.3), otherwise a document served by another party could
 *   redirect logins and token validation elsewhere;
 * - `code` must be a supported response type and, when the IdP lists PKCE
 *   methods, `S256` must be one of them;
 * - browser endpoints must pass the SSRF guard's scheme check.
 *
 * Docker setups (Externa's `compose.oidc.yaml`): `discovery_base` replaces the
 * issuer when fetching the document, and `server_origin` replaces scheme and
 * host of the server-side endpoints. The issuer itself is never rewritten, so
 * `iss` is still checked against what the browser sees.
 */
final readonly class DiscoveryService
{
    public const string WELL_KNOWN_PATH = '/.well-known/openid-configuration';

    public function __construct(
        private IdentityProviderHttpService $identityProviderHttp,
        private RemoteUrlGuard $remoteUrlGuard,
        private UrlGuardOptions $urlGuardOptions,
        private CacheRepository $cache,
        private int $cacheSeconds,
        private ?string $discoveryBase,
        private ?string $serverOrigin,
    ) {}

    /**
     * @throws IdentityProviderRequestException when the document cannot be fetched or trusted
     */
    public function discover(ProviderConfigurationData $configuration): DiscoveryDocumentData
    {
        $cacheKey = $this->cacheKey($configuration);
        $cachedAttributes = $this->cache->get($cacheKey);

        if (is_array($cachedAttributes)) {
            /** @var array<string, mixed> $cachedAttributes */
            return DiscoveryDocumentData::fromArray($cachedAttributes);
        }

        $discoveryDocument = $this->fetch($configuration);
        $this->cache->put($cacheKey, $discoveryDocument->toArray(), $this->cacheSeconds);

        return $discoveryDocument;
    }

    /**
     * Drops the cached document, for example after the settings changed or
     * when `oidc:configure` tests a new issuer.
     */
    public function forget(ProviderConfigurationData $configuration): void
    {
        $this->cache->forget($this->cacheKey($configuration));
    }

    public function discoveryUrl(ProviderConfigurationData $configuration): string
    {
        return rtrim($this->discoveryBase ?? $configuration->issuer, '/').self::WELL_KNOWN_PATH;
    }

    /**
     * @throws IdentityProviderRequestException
     */
    private function fetch(ProviderConfigurationData $configuration): DiscoveryDocumentData
    {
        $metadata = $this->identityProviderHttp->getJson($this->discoveryUrl($configuration));

        $issuer = $this->requiredUrl($metadata, 'issuer');

        if ($issuer !== $configuration->issuer) {
            throw new IdentityProviderRequestException(
                "Discovery issuer [{$issuer}] does not match the configured issuer [{$configuration->issuer}]."
            );
        }

        $responseTypes = $this->stringList($metadata, 'response_types_supported');

        if ($responseTypes !== null && ! in_array('code', $responseTypes, true)) {
            throw new IdentityProviderRequestException('The IdP does not support the authorization code flow.');
        }

        $codeChallengeMethods = $this->stringList($metadata, 'code_challenge_methods_supported');

        if ($codeChallengeMethods !== null && ! in_array('S256', $codeChallengeMethods, true)) {
            throw new IdentityProviderRequestException('The IdP does not support PKCE with S256.');
        }

        $authorizationEndpoint = $this->requiredUrl($metadata, 'authorization_endpoint');
        $endSessionEndpoint = $this->optionalUrl($metadata, 'end_session_endpoint');

        $this->assertBrowserUrlIsSafe($authorizationEndpoint);

        if ($endSessionEndpoint !== null) {
            $this->assertBrowserUrlIsSafe($endSessionEndpoint);
        }

        $userinfoEndpoint = $this->optionalUrl($metadata, 'userinfo_endpoint');

        return new DiscoveryDocumentData(
            issuer: $issuer,
            authorizationEndpoint: $authorizationEndpoint,
            tokenEndpoint: $this->toServerUrl($this->requiredUrl($metadata, 'token_endpoint')),
            jwksUri: $this->toServerUrl($this->requiredUrl($metadata, 'jwks_uri')),
            userinfoEndpoint: $userinfoEndpoint === null ? null : $this->toServerUrl($userinfoEndpoint),
            endSessionEndpoint: $endSessionEndpoint,
            idTokenSigningAlgorithms: $this->stringList($metadata, 'id_token_signing_alg_values_supported') ?? ['RS256'],
            isAuthorizationResponseIssuerSupported: ($metadata['authorization_response_iss_parameter_supported'] ?? false) === true,
        );
    }

    /**
     * @throws IdentityProviderRequestException
     */
    private function assertBrowserUrlIsSafe(string $url): void
    {
        try {
            $this->remoteUrlGuard->assertBrowserUrlIsSafe($url, $this->urlGuardOptions);
        } catch (UnsafeUrl $exception) {
            throw new IdentityProviderRequestException(
                IdentityProviderHttpService::messageForUnsafeUrl(
                    $exception,
                    (string) parse_url($url, PHP_URL_HOST),
                ),
                previous: $exception,
            );
        }
    }

    private function toServerUrl(string $url): string
    {
        if ($this->serverOrigin === null) {
            return $url;
        }

        // preg_replace returns string for this subject; cast keeps the return type honest.
        return (string) preg_replace('#^https?://[^/]+#i', rtrim($this->serverOrigin, '/'), $url); // @pest-mutate-ignore: RemoveStringCast
    }

    /**
     * Hash payload is issuer, discovery base and server origin separated by NUL
     * so a common prefix cannot collide (e.g. `/realms/a` vs `/realms/ab`).
     */
    private function cacheKey(ProviderConfigurationData $configuration): string
    {
        $payload = implode("\0", [
            $configuration->issuer,
            (string) $this->discoveryBase, // @pest-mutate-ignore: RemoveStringCast — null and '' hash the same in implode
            (string) $this->serverOrigin, // @pest-mutate-ignore: RemoveStringCast — null and '' hash the same in implode
        ]);

        return 'oidc:discovery:'.hash('sha256', $payload);
    }

    /**
     * @param  array<string, mixed>  $metadata
     *
     * @throws IdentityProviderRequestException
     */
    private function requiredUrl(array $metadata, string $key): string
    {
        return $this->optionalUrl($metadata, $key)
            ?? throw new IdentityProviderRequestException("Discovery document has no [{$key}].");
    }

    /**
     * @param  array<string, mixed>  $metadata
     */
    private function optionalUrl(array $metadata, string $key): ?string
    {
        $value = $metadata[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @param  array<string, mixed>  $metadata
     * @return list<string>|null null when the key is absent
     */
    private function stringList(array $metadata, string $key): ?array
    {
        $value = $metadata[$key] ?? null;

        if (! is_array($value)) {
            return null;
        }

        return array_values(array_filter($value, is_string(...)));
    }
}
