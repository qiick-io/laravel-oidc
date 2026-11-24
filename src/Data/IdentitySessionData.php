<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\Crypt;

/**
 * What the local session remembers about the SSO login that created it:
 * enough to send `id_token_hint` on logout and to match a back-channel
 * logout by `sid` or `sub`.
 *
 * `format_version` versions this payload (standards review M4). The value
 * always holds the plain id_token; the stored form is the data object's own
 * concern: toArray() writes version 2, with the id_token encrypted by the app
 * key (S6), and fromArray() decrypts it. Version 1 (raw id_token, beta.6 and
 * earlier) is still read, and `formatVersion` says which version was read so
 * the session can be upgraded. Readers treat a missing version as 1 (sessions
 * written before M4) and refuse any other version, or a version 2 id_token
 * that does not decrypt, so the middleware can end the session instead of
 * silently dropping revocability.
 */
final readonly class IdentitySessionData
{
    public const int FORMAT_VERSION = 2;

    /**
     * @param  list<string>|null  $amr
     */
    public function __construct(
        public string $issuer,
        public string $subject,
        public ?string $sessionId,
        #[\SensitiveParameter]
        public string $idToken,
        public int $authenticatedAt,
        public int $formatVersion = self::FORMAT_VERSION,
        public ?string $acr = null,
        public ?array $amr = null,
        public ?int $authTime = null,
    ) {}

    /**
     * @return array{
     *     issuer: string,
     *     subject: string,
     *     session_id: ?string,
     *     id_token: string,
     *     authenticated_at: int,
     *     format_version: int,
     *     acr: ?string,
     *     amr: ?list<string>,
     *     auth_time: ?int
     * }
     */
    public function toArray(): array
    {
        return [
            'issuer' => $this->issuer,
            'subject' => $this->subject,
            'session_id' => $this->sessionId,
            'id_token' => Crypt::encryptString($this->idToken),
            'authenticated_at' => $this->authenticatedAt,
            'format_version' => self::FORMAT_VERSION,
            'acr' => $this->acr,
            'amr' => $this->amr,
            'auth_time' => $this->authTime,
        ];
    }

    /**
     * Rebuilds the value from the session, or null when the stored value is
     * absent, incomplete, an unknown format_version, or a version 2 id_token
     * that does not decrypt (another app key, tampering): fail closed, M4.
     */
    public static function fromArray(mixed $attributes): ?self
    {
        if (! is_array($attributes)
            || ! is_string($attributes['issuer'] ?? null)
            || ! is_string($attributes['subject'] ?? null)
            || ! is_string($attributes['id_token'] ?? null)
            || ! is_int($attributes['authenticated_at'] ?? null)) {
            return null;
        }

        $formatVersion = $attributes['format_version'] ?? 1;

        if (! in_array($formatVersion, [1, self::FORMAT_VERSION], true)) {
            return null;
        }

        $idToken = $attributes['id_token'];

        if ($formatVersion === self::FORMAT_VERSION) {
            try {
                $idToken = Crypt::decryptString($idToken);
            } catch (DecryptException) {
                return null;
            }
        }

        $sessionId = $attributes['session_id'] ?? null;
        $authenticationContext = $attributes['acr'] ?? null;
        $authenticationMethods = $attributes['amr'] ?? null;
        $authenticationTime = $attributes['auth_time'] ?? null;

        if ($authenticationMethods !== null) {
            if (! is_array($authenticationMethods)) {
                return null;
            }

            foreach ($authenticationMethods as $authenticationMethod) {
                if (! is_string($authenticationMethod)) {
                    return null;
                }
            }

            /** @var list<string> $authenticationMethods */
        }

        return new self(
            issuer: $attributes['issuer'],
            subject: $attributes['subject'],
            sessionId: is_string($sessionId) ? $sessionId : null,
            idToken: $idToken,
            authenticatedAt: $attributes['authenticated_at'],
            formatVersion: $formatVersion,
            acr: is_string($authenticationContext) ? $authenticationContext : null,
            amr: $authenticationMethods,
            authTime: is_int($authenticationTime) ? $authenticationTime : null,
        );
    }
}
