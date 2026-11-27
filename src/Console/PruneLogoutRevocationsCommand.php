<?php

declare(strict_types=1);

namespace Qiick\Oidc\Console;

use Illuminate\Console\Command;
use Qiick\Oidc\Models\OidcLogoutRevocation;

/**
 * Prunes logout revocations once their recorded expiry and the current
 * session retention floor have passed. A dry run counts the same rows.
 */
final class PruneLogoutRevocationsCommand extends Command
{
    protected $signature = 'oidc:prune-logout-revocations
        {--chunk=1000 : Rows to delete per batch}
        {--dry-run : Report how many rows would be deleted}';

    protected $description = 'Delete expired oidc_logout_revocations rows';

    public function handle(): int
    {
        $expiredRevocations = (new OidcLogoutRevocation)->prunable();

        if ($this->option('dry-run') === true) {
            $eligibleCount = $expiredRevocations->count();
            $this->info("Would delete {$eligibleCount} expired logout revocation(s).");

            return self::SUCCESS;
        }

        $chunkOption = $this->option('chunk');
        $chunkSize = is_numeric($chunkOption) ? max(1, (int) $chunkOption) : 1000;
        $deletedCount = 0;

        do {
            $expiredIds = (clone $expiredRevocations)
                ->orderBy('id')
                ->limit($chunkSize)
                ->pluck('id');

            // A front-channel notice can refresh an expired row while pruning is running.
            $deletedCount += (clone $expiredRevocations)->whereKey($expiredIds->all())->toBase()->delete();
        } while ($expiredIds->count() === $chunkSize);

        $this->info("Deleted {$deletedCount} expired logout revocation(s).");

        return self::SUCCESS;
    }
}
