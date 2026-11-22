<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

/**
 * What the local session remembers about the SSO login that created it:
 * enough to send `id_token_hint` on logout and to match a back-channel
 * logout by `sid` or `sub`.
 *
 * `format_version` versions this payload (standards review M4). Writers always
 * emit 1. Readers treat a missing version as 1 (sessions written before M4)
 * and refuse any other version so the middleware can end the session instead
 * of silently dropping revocability.
 */
final readonly class IdentitySessionData
{
    public const int FORMAT_VERSION = 1;

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
            'id_token' => $this->idToken,
            'authenticated_at' => $this->authenticatedAt,
            'format_version' => $this->formatVersion,
            'acr' => $this->acr,
            'amr' => $this->amr,
            'auth_time' => $this->authTime,
        ];
    }

    /**
     * Rebuilds the value from the session, or null when the stored value is
     * absent, incomplete, or an unknown format_version (fail closed, M4).
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

        $formatVersion = $attributes['format_version'] ?? self::FORMAT_VERSION;

        if (! is_int($formatVersion) || $formatVersion !== self::FORMAT_VERSION) {
            return null;
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
            idToken: $attributes['id_token'],
            authenticatedAt: $attributes['authenticated_at'],
            formatVersion: $formatVersion,
            acr: is_string($authenticationContext) ? $authenticationContext : null,
            amr: $authenticationMethods,
            authTime: is_int($authenticationTime) ? $authenticationTime : null,
        );
    }
}
