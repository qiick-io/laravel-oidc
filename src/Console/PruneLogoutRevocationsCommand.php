<?php

declare(strict_types=1);

namespace Qiick\Oidc\Console;

use Illuminate\Console\Command;
use Qiick\Oidc\Models\OidcLogoutRevocation;

/**
 * `php artisan oidc:prune-logout-revocations`: deletes expired revocation rows
 * in chunks. Safe and idempotent; products should schedule it daily (M10).
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

        do {
            $expiredIds = OidcLogoutRevocation::query()
                ->where('expires_at', '<', now())
                ->orderBy('id')
                ->limit($chunkSize)
                ->pluck('id');

            if ($expiredIds->isEmpty()) {
                break;
            }

            OidcLogoutRevocation::query()->whereIn('id', $expiredIds)->delete();
            $deletedCount += $expiredIds->count();
        } while ($expiredIds->count() === $chunkSize);

        $this->info("Deleted {$deletedCount} expired logout revocation(s).");

        return self::SUCCESS;
    }
}
