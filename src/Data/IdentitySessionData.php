<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

/**
 * What the local session remembers about the SSO login that created it:
 * enough to send `id_token_hint` on logout and to match a back-channel
 * logout by `sid` or `sub`.
 */
final readonly class IdentitySessionData
{
    public function __construct(
        public string $issuer,
        public string $subject,
        public ?string $sessionId,
        #[\SensitiveParameter]
        public string $idToken,
        public int $authenticatedAt,
    ) {}

    /**
     * @return array{issuer: string, subject: string, session_id: ?string, id_token: string, authenticated_at: int}
     */
    public function toArray(): array
    {
        return [
            'issuer' => $this->issuer,
            'subject' => $this->subject,
            'session_id' => $this->sessionId,
            'id_token' => $this->idToken,
            'authenticated_at' => $this->authenticatedAt,
        ];
    }

    /**
     * Rebuilds the value from the session, or null when the stored value is
     * not a complete identity (no SSO login, or written by another version).
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

        $sessionId = $attributes['session_id'] ?? null;

        return new self(
            issuer: $attributes['issuer'],
            subject: $attributes['subject'],
            sessionId: is_string($sessionId) ? $sessionId : null,
            idToken: $attributes['id_token'],
            authenticatedAt: $attributes['authenticated_at'],
        );
    }
}
