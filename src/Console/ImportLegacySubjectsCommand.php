<?php

declare(strict_types=1);

namespace Qiick\Oidc\Console;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Schema;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Models\UserIdentity;

/**
 * `php artisan oidc:import-legacy-subjects`: copies the `sub` that Externa and
 * Excubia App stored in `users.oidc_sub` into `user_identities`, with the
 * issuer of the configured SSO provider (design section 4, "Linking"). Users keep signing in with
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
        {--issuer= : Issuer of those subjects (default: the issuer of the configured SSO provider; required while SSO is off)}
        {--dry-run : Report what would be imported without writing (works before the package migration)}';

    protected $description = 'Import legacy users.oidc_sub values into user_identities';

    /**
     * The issuer stamped on every imported identity is the one logins use:
     * `--issuer`, else the bound configuration repository (an app may keep
     * its SSO settings in the database). While SSO is not configured there is
     * no trustworthy default (config may hold a stale issuer), so the import
     * then needs `--issuer` (#38).
     */
    public function handle(ProviderConfigurationRepositoryContract $configurationRepository): int
    {
        $columnOption = $this->option('column');
        $column = is_string($columnOption) && $columnOption !== '' ? $columnOption : 'oidc_sub';
        $issuerOption = $this->option('issuer');
        $issuer = match (true) {
            is_string($issuerOption) && $issuerOption !== '' => $issuerOption,
            $configurationRepository->isEnabled() => $configurationRepository->configuration()->issuer,
            default => null,
        };
        $userModel = UserIdentity::userModel();
        $usersTable = (new $userModel)->getTable();

        if ($issuer === null) {
            $this->error('No issuer: SSO is not configured yet, so pass --issuer explicitly.');

            return self::FAILURE;
        }

        if (! Schema::hasColumn($usersTable, $column)) {
            $this->error("The [{$usersTable}] table has no [{$column}] column.");

            return self::FAILURE;
        }

        $counts = ['imported' => 0, 'already_linked' => 0, 'conflicts' => 0];
        $isDryRun = $this->option('dry-run') === true;
        $identityModel = new UserIdentity;
        $identitiesTable = $identityModel->getTable();
        // A dry run is most useful before the package migration has run, so
        // it does not need the table: every subject then counts as new.
        $hasIdentitiesTable = $identityModel->getConnection()->getSchemaBuilder()->hasTable($identitiesTable);

        if (! $hasIdentitiesTable && ! $isDryRun) {
            $this->error("The [{$identitiesTable}] table does not exist: run php artisan migrate first.");

            return self::FAILURE;
        }

        if (! $hasIdentitiesTable) {
            $this->warn("The [{$identitiesTable}] table does not exist yet (run php artisan migrate): every subject counts as new.");
        }

        $userModel::query()->whereNotNull($column)->where($column, '!=', '')->orderBy('id')
            ->each(function (Model $user) use ($column, $issuer, $isDryRun, $hasIdentitiesTable, &$counts): void {
                $userKey = $user->getKey();
                $userKey = is_int($userKey) || is_string($userKey) ? (string) $userKey : '';
                $subjectValue = $user->getAttribute($column);
                $subject = is_string($subjectValue) || is_int($subjectValue) ? (string) $subjectValue : '';
                // OIDC Core 2 caps `sub` at 255 characters, the size of the
                // column: MySQL would silently truncate a longer one.
                if (strlen($subject) > 255) {
                    $counts['conflicts']++;
                    $this->warn("User {$userKey}: the legacy subject is longer than 255 characters; skipped.");

                    return;
                }

                if (! $hasIdentitiesTable) {
                    $counts['imported']++;

                    return;
                }

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

                // insertOrIgnore is atomic on every database: a login that
                // linked the user or this sub after the checks above makes it
                // insert nothing, and the row it wrote is reported instead.
                $isInserted = $isDryRun || UserIdentity::query()->insertOrIgnore([
                    'public_id' => (new UserIdentity)->newUniqueId(),
                    'user_id' => $user->getKey(),
                    'issuer' => $issuer,
                    'subject' => $subject,
                    'link_method' => 'legacy_import',
                    'created_at' => Date::now(),
                    'updated_at' => Date::now(),
                ]) === 1;

                if (! $isInserted) {
                    $isSameLink = UserIdentity::query()->where('issuer', $issuer)->where('subject', $subject)->where('user_id', $user->getKey())->exists();
                    $counts[$isSameLink ? 'already_linked' : 'conflicts']++;

                    if (! $isSameLink) {
                        $this->warn("User {$userKey}: linked concurrently to another identity of this issuer; skipped.");
                    }

                    return;
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
