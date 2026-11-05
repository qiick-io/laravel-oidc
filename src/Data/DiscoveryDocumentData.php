<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

/**
 * The parts of an OpenID Provider metadata document (OIDC Discovery 1.0, 3)
 * the package uses, after validation and the optional Docker host rewrite.
 *
 * `authorizationEndpoint` and `endSessionEndpoint` are browser URLs and are
 * never rewritten. The other endpoints are called by the server.
 */
final readonly class DiscoveryDocumentData
{
    /**
     * @param  list<string>  $idTokenSigningAlgorithms  `id_token_signing_alg_values_supported`
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
        ];
    }

    /**
     * Rebuilds the value from the cached array written by toArray().
     *
     * @param  array<string, mixed>  $attributes
     */
    public static function fromArray(array $attributes): self
    {
        /** @var array{issuer: string, authorizationEndpoint: string, tokenEndpoint: string, jwksUri: string, userinfoEndpoint: ?string, endSessionEndpoint: ?string, idTokenSigningAlgorithms: list<string>, isAuthorizationResponseIssuerSupported: bool} $attributes */
        return new self(...$attributes);
    }
}
