<?php

declare(strict_types=1);

namespace Qiick\Oidc\Console;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Qiick\Oidc\Models\UserIdentity;

/**
 * `php artisan oidc:import-legacy-subjects`: copies the `sub` that Externa and
 * Excubia App stored in `users.oidc_sub` into `user_identities`, with the
 * configured issuer (design section 4, "Linking"). Users keep signing in with
 * the same IdP account after the switch to the package.
 *
 * Idempotent: identities that already exist are skipped, and an identity
 * already linked to another user is reported, never moved. The legacy column
 * is left in place; drop it in a later forward-only migration.
 */
final class ImportLegacySubjectsCommand extends Command
{
    protected $signature = 'oidc:import-legacy-subjects
        {--column=oidc_sub : Column of the users table that holds the legacy sub}
        {--issuer= : Issuer of those subjects (default: the configured OIDC issuer)}
        {--dry-run : Report what would be imported without writing}';

    protected $description = 'Import legacy users.oidc_sub values into user_identities';

    public function handle(): int
    {
        $columnOption = $this->option('column');
        $column = is_string($columnOption) && $columnOption !== '' ? $columnOption : 'oidc_sub';
        $issuer = $this->option('issuer');
        $issuer = is_string($issuer) && $issuer !== '' ? $issuer : Config::get('oidc.issuer');
        $userModel = UserIdentity::userModel();
        $usersTable = (new $userModel)->getTable();

        if (! is_string($issuer) || $issuer === '') {
            $this->error('No issuer: pass --issuer or set OIDC_ISSUER.');

            return self::FAILURE;
        }

        if (! Schema::hasColumn($usersTable, $column)) {
            $this->error("The [{$usersTable}] table has no [{$column}] column.");

            return self::FAILURE;
        }

        $counts = ['imported' => 0, 'already_linked' => 0, 'conflicts' => 0];
        $isDryRun = $this->option('dry-run') === true;

        $userModel::query()->whereNotNull($column)->where($column, '!=', '')->orderBy('id')
            ->each(function (Model $user) use ($column, $issuer, $isDryRun, &$counts): void {
                $userKey = $user->getKey();
                $userKey = is_int($userKey) || is_string($userKey) ? (string) $userKey : '';
                $subjectValue = $user->getAttribute($column);
                $subject = is_string($subjectValue) || is_int($subjectValue) ? (string) $subjectValue : '';
                $existing = UserIdentity::query()->where('issuer', $issuer)->where('subject', $subject)->first();

                if ($existing !== null) {
                    $outcome = (string) $existing->user_id === $userKey ? 'already_linked' : 'conflicts';
                    $counts[$outcome]++;

                    if ($outcome === 'conflicts') {
                        $this->warn("User {$userKey}: this sub is already linked to user {$existing->user_id}; skipped.");
                    }

                    return;
                }

                // One identity per user and issuer (unique user_id, issuer):
                // a user auto-linked to another subject is left as it is.
                $isUserLinkedToIssuer = UserIdentity::query()->where('user_id', $user->getKey())->where('issuer', $issuer)->exists();

                if ($isUserLinkedToIssuer) {
                    $counts['conflicts']++;
                    $this->warn("User {$userKey}: already linked to another subject of this issuer; skipped.");

                    return;
                }

                if (! $isDryRun) {
                    DB::transaction(fn () => UserIdentity::query()->create([
                        'user_id' => $user->getKey(),
                        'issuer' => $issuer,
                        'subject' => $subject,
                        'link_method' => 'legacy_import',
                    ]));
                }

                $counts['imported']++;
            });

        $this->info(sprintf(
            '%s %d identit%s for issuer %s; %d already linked, %d conflicts.',
            $isDryRun ? 'Would import' : 'Imported',
            $counts['imported'],
            $counts['imported'] === 1 ? 'y' : 'ies',
            $issuer,
            $counts['already_linked'],
            $counts['conflicts'],
        ));

        return $counts['conflicts'] > 0 ? self::FAILURE : self::SUCCESS;
    }
}
