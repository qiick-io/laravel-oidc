<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Qiick\Oidc\Data\DiscoveryDocumentData;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Exceptions\InvalidTokenException;

/**
 * Reads the userinfo endpoint (OIDC Core 5.3) with the access token of the
 * login that just completed.
 *
 * The response is not signed, so its `sub` must equal the validated id_token
 * `sub` (OIDC Core 5.3.4); otherwise a mixed-up or substituted response could
 * attach another person's email to this login.
 *
 * ponytail: only plain JSON responses. A signed or encrypted userinfo response
 * (`application/jwt`) is refused; add it if an IdP needs it.
 *
 * @internal Not part of the public API (docs/public-api.md); it can change in any release.
 */
final readonly class UserinfoService
{
    public function __construct(
        private IdentityProviderHttpService $identityProviderHttp,
    ) {}

    /**
     * @return array<string, mixed> the userinfo claims; empty when the IdP has no userinfo endpoint
     *
     * @throws IdentityProviderRequestException when the request fails
     * @throws InvalidTokenException when `sub` does not match the id_token
     */
    public function fetch(DiscoveryDocumentData $discovery, #[\SensitiveParameter] string $accessToken, string $expectedSubject): array
    {
        if ($discovery->userinfoEndpoint === null) {
            return [];
        }

        $claims = $this->identityProviderHttp->getJson($discovery->userinfoEndpoint, ['Authorization' => 'Bearer '.$accessToken]);

        if (($claims['sub'] ?? null) !== $expectedSubject) {
            throw new InvalidTokenException('Userinfo [sub] does not match the id_token.');
        }

        return $claims;
    }
}
