<?php

declare(strict_types=1);

namespace Qiick\Oidc\Console;

use Illuminate\Console\Command;
use Qiick\Oidc\Models\OidcLogoutRevocation;

/**
 * `php artisan oidc:prune-logout-revocations`: deletes rows whose write-time
 * `expires_at` has passed. That timestamp was fixed at insert as the max of
 * the configured lifetimes (`revocation_ttl` and `session.lifetime`) and the
 * token validation window; prune never recomputes those TTLs (M10).
 */
final class PruneLogoutRevocationsCommand extends Command
{
    protected $signature = 'oidc:prune-logout-revocations
        {--chunk=1000 : Rows to delete per batch}';

    protected $description = 'Delete expired oidc_logout_revocations rows';

    public function handle(): int
    {
        $chunkOption = $this->option('chunk');
        $chunkSize = is_numeric($chunkOption) ? max(1, (int) $chunkOption) : 1000;
        $deletedCount = 0;
        // Safety floor: never prune a row younger than the max of the
        // lifetimes configured now, even if a stale expires_at is already past.
        $maximumConfiguredLifetimeSeconds = OidcLogoutRevocation::maximumConfiguredLifetimeSeconds();

        do {
            $expiredIds = OidcLogoutRevocation::query()
                ->where('expires_at', '<', now())
                ->where('received_at', '<', now()->subSeconds($maximumConfiguredLifetimeSeconds))
                ->orderBy('id')
                ->limit($chunkSize)
                ->pluck('id');

            OidcLogoutRevocation::query()->whereIn('id', $expiredIds)->delete();
            $deletedCount += $expiredIds->count();
        } while ($expiredIds->count() === $chunkSize);

        $this->info("Deleted {$deletedCount} expired logout revocation(s).");

        return self::SUCCESS;
    }
}
