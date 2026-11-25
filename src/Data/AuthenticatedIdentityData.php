<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

use Firebase\JWT\JWT;
use Throwable;

/**
 * The result of a successful authorization code flow: who the IdP says the
 * user is, after the id_token passed every check.
 *
 * The identity key is the pair (issuer, subject), never the email. The raw
 * id_token is kept for RP-initiated logout (`id_token_hint`); the access token
 * only lives for the current request (userinfo) and is not stored.
 *
 * Trust-sensitive claims (`auth_time`, `amr`, `acr`) are read from this
 * validated id_token payload only (OIDC Core 2; standards review M2).
 */
final readonly class AuthenticatedIdentityData
{
    /**
     * @param  array<string, mixed>  $claims  the validated id_token claims
     * @param  bool  $isRequestedAuthenticationContextMet  false when the login asked for an `acr` and the
     *                                                     id_token has none of the requested values
     */
    public function __construct(
        public string $issuer,
        public string $subject,
        public array $claims,
        #[\SensitiveParameter]
        public string $idToken,
        #[\SensitiveParameter]
        public string $accessToken,
        public ?string $sessionId,
        public bool $isRequestedAuthenticationContextMet = true,
    ) {}

    public function claim(string $name): mixed
    {
        return $this->claims[$name] ?? null;
    }

    /**
     * Unix `auth_time` from the validated id_token, or null when absent.
     */
    public function authTime(): ?int
    {
        $authenticationTime = $this->claim('auth_time');

        return is_int($authenticationTime) ? $authenticationTime : null;
    }

    /**
     * Authentication Context Class Reference (`acr`), when the IdP sent one.
     */
    public function acr(): ?string
    {
        $authenticationContext = $this->claim('acr');

        return is_string($authenticationContext) && $authenticationContext !== '' ? $authenticationContext : null;
    }

    /**
     * Authentication Method References (`amr`) as a list of strings (RFC 8176).
     *
     * @return list<string>|null
     */
    public function amr(): ?array
    {
        $authenticationMethods = $this->claim('amr');

        if (! is_array($authenticationMethods)) {
            return null;
        }

        $stringMethods = [];

        foreach ($authenticationMethods as $authenticationMethod) {
            if (! is_string($authenticationMethod) || $authenticationMethod === '') {
                return null;
            }

            $stringMethods[] = $authenticationMethod;
        }

        return $stringMethods;
    }

    /**
     * Signing `alg` from the validated id_token JOSE header (already checked).
     */
    public function idTokenAlgorithm(): ?string
    {
        $segments = explode('.', $this->idToken);

        if (count($segments) !== 3) {
            return null;
        }

        try {
            $header = json_decode(JWT::urlsafeB64Decode($segments[0]), true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return null;
        }

        $algorithm = is_array($header) ? $header['alg'] ?? null : null;

        return is_string($algorithm) && $algorithm !== '' ? $algorithm : null;
    }

    /**
     * Given and family name from `given_name` / `family_name`, or from `name`
     * split on its last word; null when the IdP sent no name at all.
     */
    public function personName(): ?PersonNameData
    {
        return PersonNameData::fromClaims($this->claims);
    }
}
