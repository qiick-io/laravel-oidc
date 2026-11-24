<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

/**
 * The parts of an OpenID Provider metadata document (OIDC Discovery 1.0, 3)
 * the package uses, after validation and the optional Docker host rewrite.
 *
 * `authorizationEndpoint` and `endSessionEndpoint` are browser URLs and are
 * never rewritten. The other endpoints are called by the server.
 *
 * The capability flags (standards review S5) are informational: they default
 * to false as in their specs, and the package never refuses an IdP for one.
 * They are trailing and optional, so a discovery document cached by an older
 * release still rebuilds.
 *
 * @internal Not part of the public API (docs/PUBLIC-API.md); it can change in any release.
 */
final readonly class DiscoveryDocumentData
{
    /**
     * @param  list<string>  $idTokenSigningAlgorithms  `id_token_signing_alg_values_supported`
     * @param  list<string>|null  $acrValuesSupported  `acr_values_supported` (DISC §3), null when not advertised
     */
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $userinfoEndpoint,
        public ?string $endSessionEndpoint,
        public array $idTokenSigningAlgorithms,
        public bool $isAuthorizationResponseIssuerSupported,
        public bool $isFrontChannelLogoutSupported = false,
        public bool $isFrontChannelLogoutSessionSupported = false,
        public bool $isBackChannelLogoutSupported = false,
        public bool $isBackChannelLogoutSessionSupported = false,
        public ?array $acrValuesSupported = null,
        public bool $isClaimsParameterSupported = false,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'issuer' => $this->issuer,
            'authorizationEndpoint' => $this->authorizationEndpoint,
            'tokenEndpoint' => $this->tokenEndpoint,
            'jwksUri' => $this->jwksUri,
            'userinfoEndpoint' => $this->userinfoEndpoint,
            'endSessionEndpoint' => $this->endSessionEndpoint,
            'idTokenSigningAlgorithms' => $this->idTokenSigningAlgorithms,
            'isAuthorizationResponseIssuerSupported' => $this->isAuthorizationResponseIssuerSupported,
            'isFrontChannelLogoutSupported' => $this->isFrontChannelLogoutSupported,
            'isFrontChannelLogoutSessionSupported' => $this->isFrontChannelLogoutSessionSupported,
            'isBackChannelLogoutSupported' => $this->isBackChannelLogoutSupported,
            'isBackChannelLogoutSessionSupported' => $this->isBackChannelLogoutSessionSupported,
            'acrValuesSupported' => $this->acrValuesSupported,
            'isClaimsParameterSupported' => $this->isClaimsParameterSupported,
        ];
    }

    /**
     * Rebuilds the value from the cached array written by toArray().
     *
     * @param  array<string, mixed>  $attributes
     */
    public static function fromArray(array $attributes): self
    {
        /** @var array{issuer: string, authorizationEndpoint: string, tokenEndpoint: string, jwksUri: string, userinfoEndpoint: ?string, endSessionEndpoint: ?string, idTokenSigningAlgorithms: list<string>, isAuthorizationResponseIssuerSupported: bool, isFrontChannelLogoutSupported?: bool, isFrontChannelLogoutSessionSupported?: bool, isBackChannelLogoutSupported?: bool, isBackChannelLogoutSessionSupported?: bool, acrValuesSupported?: ?list<string>, isClaimsParameterSupported?: bool} $attributes */
        return new self(...$attributes);
    }
}
