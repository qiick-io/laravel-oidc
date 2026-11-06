<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

/**
 * The result of a successful authorization code flow: who the IdP says the
 * user is, after the id_token passed every check.
 *
 * The identity key is the pair (issuer, subject), never the email. The raw
 * id_token is kept for RP-initiated logout (`id_token_hint`); the access token
 * only lives for the current request (userinfo) and is not stored.
 */
final readonly class AuthenticatedIdentityData
{
    /**
     * @param  array<string, mixed>  $claims  the validated id_token claims
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
    ) {}

    public function claim(string $name): mixed
    {
        return $this->claims[$name] ?? null;
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
