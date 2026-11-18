<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Qiick\Oidc\Data\DiscoveryDocumentData;
use Qiick\Oidc\Data\ProviderConfigurationData;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Exceptions\InvalidTokenException;

/**
 * Validates the `id_token` of the token response (OIDC Core 3.1.3.7): the
 * shared JWT checks, plus a non-empty, trimmed `sub` and the `nonce` this
 * login sent.
 *
 * The nonce binds the token to the browser session that started the login,
 * so a token captured elsewhere cannot be replayed into another session.
 */
final readonly class IdTokenValidatorService
{
    /**
     * OIDC Core 2: `sub` is at most 255 ASCII characters.
     */
    private const int MAXIMUM_SUBJECT_LENGTH = 255;

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

        return $claims;
    }
}
