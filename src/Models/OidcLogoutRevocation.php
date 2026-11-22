<?php

declare(strict_types=1);

namespace Qiick\Oidc\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;

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
 * @property string $channel
 * @property CarbonImmutable $received_at
 * @property CarbonImmutable $expires_at
 * @property array<string, mixed>|null $metadata
 * @property CarbonImmutable|null $created_at
 * @property CarbonImmutable|null $updated_at
 */
class OidcLogoutRevocation extends Model
{
    use MassPrunable;

    protected $table = 'oidc_logout_revocations';

    protected $guarded = ['id'];

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
     * Max of `oidc.backchannel_logout.revocation_ttl` and `session.lifetime`
     * (minutes → seconds), matching the write-time lifetime floor.
     */
    public static function maximumConfiguredLifetimeSeconds(): int
    {
        $sessionLifetimeSeconds = max(1, Config::integer('session.lifetime', 120)) * 60;
        $configuredSeconds = Config::get('oidc.backchannel_logout.revocation_ttl');

        if (is_int($configuredSeconds) && $configuredSeconds > 0) {
            return max($configuredSeconds, $sessionLifetimeSeconds);
        }

        return $sessionLifetimeSeconds;
    }
}
