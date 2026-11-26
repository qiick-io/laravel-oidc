<?php

declare(strict_types=1);

namespace Qiick\Oidc\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Qiick\Oidc\Models\Concerns\GuardsIdByDefaultTrait;

/**
 * One validated OIDC logout revocation (back-channel or front-channel).
 *
 * Rows are never exposed outside the package: no public_id. The unique
 * (issuer, jti) key is the durable BCL replay check; the cache only
 * accelerates reads (standards review M10).
 *
 * @property int $id
 * @property string $issuer
 * @property string|null $sid
 * @property string|null $sub
 * @property string|null $jti
 * @property string|null $replay_key
 * @property string $channel
 * @property CarbonImmutable $received_at
 * @property CarbonImmutable $expires_at
 * @property array<string, mixed>|null $metadata
 * @property CarbonImmutable|null $created_at
 * @property CarbonImmutable|null $updated_at
 */
class OidcLogoutRevocation extends Model
{
    use GuardsIdByDefaultTrait;
    use MassPrunable;

    protected $table = 'oidc_logout_revocations';

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'received_at' => 'immutable_datetime',
            'expires_at' => 'immutable_datetime',
            'metadata' => 'array',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }

    /**
     * Rows past their write-time expires_at (and older than the max of the
     * configured lifetimes) can no longer revoke a live session or be replayed.
     *
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        return static::query()
            ->where('expires_at', '<', now())
            ->where('received_at', '<', now()->subSeconds(self::maximumConfiguredLifetimeSeconds()));
    }

    /**
     * Larger of `oidc.backchannel_logout.revocation_ttl` and the host's session
     * lifetime, subject to the configured ceiling for the revocation ledger.
     */
    public static function maximumConfiguredLifetimeSeconds(): int
    {
        $maximumRetentionSeconds = self::maximumRetentionSeconds();
        $sessionLifetimeMinutes = min(max(1, Config::integer('session.lifetime')), intdiv($maximumRetentionSeconds, 60));
        $sessionLifetimeSeconds = $sessionLifetimeMinutes * 60;
        $configuredSeconds = Config::get('oidc.backchannel_logout.revocation_ttl');

        return min($maximumRetentionSeconds, max($sessionLifetimeSeconds, is_int($configuredSeconds) ? $configuredSeconds : $sessionLifetimeSeconds));
    }

    /** Provide the default even if the host cached its config before this key existed. */
    public static function maximumRetentionSeconds(): int
    {
        return Config::integer('oidc.backchannel_logout.max_retention_seconds', 2_592_000);
    }

    /** Compare in minutes so even an oversized session lifetime cannot overflow. */
    public static function isSessionLifetimeCovered(): bool
    {
        return max(1, Config::integer('session.lifetime')) <= intdiv(self::maximumRetentionSeconds(), 60);
    }
}
