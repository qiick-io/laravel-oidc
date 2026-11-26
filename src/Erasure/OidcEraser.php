<?php

declare(strict_types=1);

namespace Qiick\Oidc\Erasure;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Qiick\Oidc\Events\SubjectErasedEvent;
use Qiick\Oidc\Models\OidcLogoutRevocation;
use Qiick\Oidc\Models\UserIdentity;
use Qiick\Oidc\Services\SessionRevocationService;
use RuntimeException;
use SensitiveParameter;

/**
 * Erases locally linked OIDC identities and the logout state attributable to them.
 *
 * @api
 *
 * @phpstan-import-type StoreCounts from ErasureReport
 */
final readonly class OidcEraser
{
    public const string DELETE = 'delete';

    public const string ANONYMISE = 'anonymise';

    public function __construct(
        private CacheRepository $cache,
        private Dispatcher $events,
        private string $cacheStoreName,
    ) {}

    /**
     * The app disables sign-in and removes its sessions before calling this eraser.
     * The user row remains owned by the app. Cache eviction and the aggregate event
     * run only after the outermost database transaction commits.
     *
     * @param  list<string>  $publicIds
     * @param  list<string>  $identifiers
     *
     * @throws InvalidArgumentException
     * @throws OrganisationScopeUnsupportedException
     */
    public function erase(
        #[SensitiveParameter] string $userId,
        #[SensitiveParameter] string $userPublicId,
        string $mode,
        #[SensitiveParameter] array $publicIds = [],
        #[SensitiveParameter] array $identifiers = [],
        ?string $organisationId = null,
        bool $dryRun = false,
    ): ErasureReport {
        $this->validate($userId, $userPublicId, $mode, $publicIds, $identifiers);

        if ($organisationId !== null) {
            throw new OrganisationScopeUnsupportedException('OIDC identity erasure is global.');
        }

        $connection = DB::connection();

        try {
            return $connection->transaction(function () use ($connection, $userId, $mode, $publicIds, $dryRun): ErasureReport {
                $identities = UserIdentity::query()
                    ->where(function (Builder $query) use ($userId, $publicIds): void {
                        $query->where('user_id', $userId)->orWhereIn('public_id', $publicIds);
                    })
                    ->orderBy('id')
                    ->lockForUpdate()
                    ->get();
                $cacheKeys = [];
                $revocations = $this->counts();

                // Capture unresolved SID-only rows before scrubbing the subject
                // that corroborates any attributable SID in this issuer.
                $issuers = $identities->map(fn (UserIdentity $identity): string => $identity->issuer)->unique();
                $unlinkedCount = $this->unlinkedCount($issuers->all());

                foreach ($identities as $identity) {
                    $this->eraseRevocations($identity, $mode, $dryRun, $cacheKeys, $revocations);

                    if (! $dryRun) {
                        $this->eraseIdentity($identity, $mode);
                    }
                }

                // Derive the subject key even without a durable row: pruning can
                // race erasure, and a cache may still hold the last cut-off.
                $cachedKeys = array_filter(
                    array_unique($cacheKeys),
                    fn (string $cacheKey): bool => $this->cache->has($cacheKey),
                );
                $report = new ErasureReport('qiick/laravel-oidc', $mode, $dryRun, [
                    'user_identities' => $mode === self::DELETE
                        ? $this->counts(deleted: $identities->count())
                        : $this->counts(anonymised: $identities->count()),
                    'oidc_logout_revocations' => $revocations,
                    'cleartext:oidc_logout_revocations.sid' => $this->counts(kept: $unlinkedCount),
                    'cleartext:oidc_logout_revocations.replay_key' => $this->counts(kept: $revocations['kept']),
                    'cache:'.$this->cacheStoreName => $this->counts(deleted: count($cachedKeys)),
                ]);

                if (! $dryRun) {
                    $connection->afterCommit(function () use ($cachedKeys, $report): void {
                        foreach ($cachedKeys as $cacheKey) {
                            $this->cache->forget($cacheKey);
                        }

                        $this->events->dispatch(new SubjectErasedEvent($report));
                    });
                }

                return $report;
            });
        } catch (QueryException) {
            // QueryException includes interpolated bindings, including subject IDs.
            throw new RuntimeException('OIDC erasure database operation failed.');
        }
    }

    /**
     * Match session-only rows only within the issuer and only when a subject
     * revocation corroborates the SID without a competing subject.
     *
     * @param  list<string>  $cacheKeys
     * @param  StoreCounts  $counts
     */
    private function eraseRevocations(UserIdentity $identity, string $mode, bool $dryRun, array &$cacheKeys, array &$counts): void
    {
        $issuerRevocations = OidcLogoutRevocation::query()->where('issuer', $identity->issuer);
        $corroboratingRevocations = (clone $issuerRevocations)
            ->where('sub', $identity->subject)
            ->whereNotIn('sid', (clone $issuerRevocations)->where('sub', '<>', $identity->subject)->whereNotNull('sid')->select('sid'))
            ->distinct()
            ->get(['sid']);
        $cacheKeys[] = SessionRevocationService::cacheKey('sub', $identity->issuer, $identity->subject);
        $knownSessionIds = [];

        foreach ($corroboratingRevocations as $revocation) {
            if ($revocation->sid !== null) {
                $knownSessionIds[] = $revocation->sid;
                $cacheKeys[] = SessionRevocationService::cacheKey('sid', $identity->issuer, $revocation->sid);
            }
        }

        $linkedRevocations = $issuerRevocations
            ->where(function (Builder $query) use ($identity, $knownSessionIds): void {
                $query->where('sub', $identity->subject)
                    ->orWhere(fn (Builder $query): Builder => $query->whereNull('sub')->whereIn('sid', $knownSessionIds));
            })
            ->orderBy('id')
            ->lockForUpdate()
            ->get();

        foreach ($linkedRevocations as $revocation) {
            $hasReplayEvidence = $revocation->replay_key !== null;
            $shouldDelete = $mode === self::DELETE && ! $hasReplayEvidence;
            $counts[$shouldDelete ? 'deleted' : 'anonymised']++;

            if ($hasReplayEvidence) {
                $counts['kept']++;
                $counts['reason'] = 'security_log';
            }

            if ($dryRun) {
                continue;
            }

            $row = OidcLogoutRevocation::query()->toBase()->where('id', $revocation->id);

            if ($shouldDelete) {
                $row->delete();
            } else {
                $row->update(['sub' => null, 'sid' => null, 'jti' => null, 'metadata' => null]);
            }
        }
    }

    /**
     * Unresolved SIDs are counted at issuer level because they have no local
     * owner. This count is aggregate security retention, with no user attribution.
     *
     * @param  array<int, string>  $issuers
     */
    private function unlinkedCount(array $issuers): int
    {
        return OidcLogoutRevocation::query()
            ->whereIn('issuer', $issuers)
            ->whereNull('sub')
            ->whereNotNull('sid')
            ->whereNotExists(DB::table('oidc_logout_revocations as evidence')
                ->whereColumn('evidence.issuer', 'oidc_logout_revocations.issuer')
                ->whereColumn('evidence.sid', 'oidc_logout_revocations.sid')
                ->groupBy('evidence.issuer', 'evidence.sid')
                ->havingRaw('count(distinct evidence.sub) = 1')
                ->selectRaw('1'))
            ->count();
    }

    private function eraseIdentity(UserIdentity $identity, string $mode): void
    {
        $row = UserIdentity::query()->toBase()->where('id', $identity->id);

        if ($mode === self::DELETE) {
            $row->delete();

            return;
        }

        // The sentinel is not a valid issuer. Fresh UUIDs satisfy the existing
        // unique keys without keeping a join back to the person's original IDs.
        $row->update([
            'public_id' => (string) Str::uuid(),
            'user_id' => null,
            'issuer' => 'erased',
            'subject' => (string) Str::uuid(),
            'subject_type' => null,
            'provider_key' => null,
            'link_method' => null,
            'email_at_link' => null,
            'email_verified_at_link' => null,
            'preferred_username_at_link' => null,
            'name_at_link' => null,
            'last_login_at' => null,
            'last_auth_time_at' => null,
            'last_acr' => null,
            'last_amr' => null,
            'last_id_token_alg' => null,
            'metadata' => null,
            'created_at' => null,
            'updated_at' => null,
        ]);
    }

    /**
     * @param  array<mixed>  $publicIds
     * @param  array<mixed>  $identifiers
     */
    private function validate(string $userId, string $userPublicId, string $mode, array $publicIds, array $identifiers): void
    {
        // The shipped identity owner key is a bigint. Keep textual inputs from
        // being coerced into another user's number on MySQL.
        if (! ctype_digit($userId) || (string) (int) $userId !== $userId) {
            throw new InvalidArgumentException('The OIDC user key must be a decimal integer.');
        }

        if (! in_array($mode, [self::DELETE, self::ANONYMISE], true)) {
            throw new InvalidArgumentException('Unknown OIDC erasure mode.');
        }

        foreach ([$userPublicId, ...$publicIds] as $publicId) {
            if (! is_string($publicId) || ! Str::isUuid($publicId)) {
                throw new InvalidArgumentException('OIDC erasure public IDs must be UUIDs.');
            }
        }

        foreach ($identifiers as $identifier) {
            if (! is_string($identifier) || trim($identifier) === '') {
                throw new InvalidArgumentException('OIDC erasure identifiers must be non-empty strings.');
            }
        }
    }

    /** @return StoreCounts */
    private function counts(int $deleted = 0, int $anonymised = 0, int $kept = 0): array
    {
        return ['deleted' => $deleted, 'anonymised' => $anonymised, 'kept' => $kept, 'reason' => $kept > 0 ? 'security_log' : null];
    }
}
