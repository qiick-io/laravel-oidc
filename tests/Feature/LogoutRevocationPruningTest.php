<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Qiick\Oidc\Laravel\OidcServiceProvider;
use Qiick\Oidc\Models\OidcLogoutRevocation;

/*
 * Pruning oidc_logout_revocations (standards review M10): a row goes only
 * once it can no longer revoke a live session or let a logout token be
 * replayed, in batches, and never younger than the longest configured lifetime.
 */

beforeEach(function (): void {
    Date::setTestNow('2026-11-24 12:00:00');
    Config::set(['session.lifetime' => 120, 'oidc.backchannel_logout.revocation_ttl' => null]);
});

function revocationRow(string $tokenId, string $receivedAt, string $expiresAt): OidcLogoutRevocation
{
    return OidcLogoutRevocation::query()->create([
        'issuer' => 'https://idp.example.com/realms/test',
        'sid' => 'sid-'.$tokenId,
        'jti' => $tokenId,
        'channel' => 'backchannel',
        'received_at' => Date::parse($receivedAt),
        'expires_at' => Date::parse($expiresAt),
    ]);
}

it('deletes every expired row in batches of the chosen size', function (): void {
    foreach (range(1, 5) as $rowNumber) {
        revocationRow("expired-{$rowNumber}", '2026-11-24 08:00:00', '2026-11-24 10:00:00');
    }

    $kept = revocationRow('live', '2026-11-24 11:59:00', '2026-11-24 13:59:00');

    $this->artisan('oidc:prune-logout-revocations', ['--chunk' => 2])
        ->expectsOutput('Deleted 5 expired logout revocation(s).')
        ->assertSuccessful();

    expect(OidcLogoutRevocation::query()->pluck('jti')->all())->toBe([$kept->jti]);
});

it('keeps an expired row younger than the longest configured lifetime', function (): void {
    // expires_at was written with a shorter lifetime than the one configured now.
    revocationRow('stale-expiry', '2026-11-24 11:00:00', '2026-11-24 11:30:00');

    $this->artisan('oidc:prune-logout-revocations')->expectsOutput('Deleted 0 expired logout revocation(s).');

    expect(OidcLogoutRevocation::query()->count())->toBe(1);
});

it('reports eligible rows without deleting any rows in a dry run', function (): void {
    revocationRow('expired', '2026-11-24 08:00:00', '2026-11-24 10:00:00');
    revocationRow('recent', '2026-11-24 11:00:00', '2026-11-24 11:30:00');
    revocationRow('live', '2026-11-24 09:00:00', '2026-11-24 13:00:00');

    $this->artisan('oidc:prune-logout-revocations', ['--chunk' => 1, '--dry-run' => true])
        ->expectsOutput('Would delete 1 expired logout revocation(s).')
        ->assertSuccessful();

    expect(OidcLogoutRevocation::query()->orderBy('id')->pluck('jti')->all())
        ->toBe(['expired', 'recent', 'live']);
});

it('keeps a revocation refreshed after the batch selected it', function (): void {
    $revocation = revocationRow('refreshing', '2026-11-24 08:00:00', '2026-11-24 10:00:00');
    DB::listen(function (QueryExecuted $query) use ($revocation): void {
        if (str_starts_with(strtolower($query->sql), 'select') && str_contains($query->sql, 'oidc_logout_revocations')) {
            $revocation->update(['received_at' => now(), 'expires_at' => now()->addHours(2)]);
        }
    });

    $this->artisan('oidc:prune-logout-revocations', ['--chunk' => 1])
        ->expectsOutput('Deleted 0 expired logout revocation(s).')
        ->assertSuccessful();

    expect(OidcLogoutRevocation::query()->whereKey($revocation->id)->exists())->toBeTrue();
});

it('only schedules pruning when OIDC and its schedule are enabled', function (bool $isOidcEnabled, bool $isScheduleEnabled, bool $shouldSchedulePruning): void {
    Config::set([
        'oidc.enabled' => $isOidcEnabled,
        'oidc.backchannel_logout.schedule' => $isScheduleEnabled,
    ]);
    app()->register(OidcServiceProvider::class, force: true);

    $scheduledPrunes = array_values(array_filter(
        app(Schedule::class)->events(),
        fn (Event $event): bool => str_contains($event->command ?? '', 'oidc:prune-logout-revocations'),
    ));

    expect($scheduledPrunes)->toHaveCount($shouldSchedulePruning ? 1 : 0);

    if ($shouldSchedulePruning) {
        expect($scheduledPrunes[0]->expression)->toBe('0 * * * *')
            ->and($scheduledPrunes[0]->onOneServer)->toBeTrue()
            ->and($scheduledPrunes[0]->withoutOverlapping)->toBeTrue();
    }
})->with([
    'both enabled' => [true, true, true],
    'schedule disabled' => [true, false, false],
    'OIDC disabled' => [false, true, false],
]);

it('falls back to batches of 1000, and of at least 1, for an unusable --chunk', function (string $chunk): void {
    revocationRow('expired', '2026-11-24 08:00:00', '2026-11-24 10:00:00');

    $this->artisan('oidc:prune-logout-revocations', ['--chunk' => $chunk])
        ->expectsOutput('Deleted 1 expired logout revocation(s).')
        ->assertSuccessful();
})->with(['not a number' => ['many'], 'zero' => ['0'], 'negative' => ['-3']]);

it('takes the longest of the revocation ttl and the session lifetime as the lifetime', function (mixed $revocationTtl, int $sessionMinutes, int $lifetimeSeconds): void {
    Config::set(['oidc.backchannel_logout.revocation_ttl' => $revocationTtl, 'session.lifetime' => $sessionMinutes]);

    expect(OidcLogoutRevocation::maximumConfiguredLifetimeSeconds())->toBe($lifetimeSeconds);
})->with([
    'session only' => [null, 120, 7200],
    'longer ttl' => [10_000, 120, 10_000],
    'shorter ttl' => [600, 120, 7200],
    'zero ttl' => [0, 120, 7200],
    'ttl as a string' => ['10000', 120, 7200],
    'session lifetime 0' => [null, 0, 60],
    'session lifetime 1' => [null, 1, 60],
    'week-long sessions' => [null, 10_080, 604_800],
    'maximum revocation lifetime' => [2_592_000, 120, 2_592_000],
    'maximum session lifetime' => [null, 43_200, 2_592_000],
    'revocation lifetime above the ceiling' => [2_592_001, 120, 2_592_000],
]);

it('uses a thirty-day ceiling when the host cached config without the new key', function (): void {
    Config::set('oidc.backchannel_logout', ['revocation_ttl' => null]);

    expect(OidcLogoutRevocation::maximumRetentionSeconds())->toBe(2_592_000);
});

it('lets model:prune find the same rows', function (): void {
    revocationRow('expired', '2026-11-24 08:00:00', '2026-11-24 10:00:00');
    revocationRow('recent', '2026-11-24 11:00:00', '2026-11-24 11:30:00');
    revocationRow('live', '2026-11-24 11:59:00', '2026-11-24 13:59:00');

    expect((new OidcLogoutRevocation)->prunable()->pluck('jti')->all())->toBe(['expired']);
});

it('casts its times and metadata, and never mass-assigns the id', function (): void {
    $row = OidcLogoutRevocation::query()->create([
        'id' => 999,
        'issuer' => 'https://idp.example.com/realms/test',
        'jti' => 'casts',
        'channel' => 'backchannel',
        'received_at' => '2026-11-24 12:00:00',
        'expires_at' => '2026-11-24 14:00:00',
        'metadata' => ['request_id' => 'r-1'],
    ])->fresh();

    expect($row?->id)->not->toBe(999)
        ->and($row?->received_at)->toBeInstanceOf(CarbonImmutable::class)
        ->and($row?->expires_at)->toBeInstanceOf(CarbonImmutable::class)
        ->and($row?->created_at)->toBeInstanceOf(CarbonImmutable::class)
        ->and($row?->updated_at)->toBeInstanceOf(CarbonImmutable::class)
        ->and($row?->metadata)->toBe(['request_id' => 'r-1']);
});

it('deletes in as many batches as the chunk size needs', function (int $rowCount, array $options, int $deleteQueries): void {
    $receivedAt = Date::parse('2026-11-24 08:00:00')->toImmutable();
    $rows = array_map(fn (int $rowNumber): array => [
        'issuer' => 'https://idp.example.com/realms/test',
        'jti' => "bulk-{$rowNumber}",
        'channel' => 'backchannel',
        'received_at' => $receivedAt,
        'expires_at' => $receivedAt->addHours(2),
    ], range(1, $rowCount));

    foreach (array_chunk($rows, 200) as $chunk) {
        DB::table('oidc_logout_revocations')->insert($chunk);
    }

    $deletes = 0;
    DB::listen(function (QueryExecuted $query) use (&$deletes): void {
        $deletes += str_starts_with(strtolower($query->sql), 'delete') ? 1 : 0;
    });

    $this->artisan('oidc:prune-logout-revocations', $options)->assertSuccessful();

    expect($deletes)->toBe($deleteQueries)
        ->and(OidcLogoutRevocation::query()->count())->toBe(0);
})->with([
    'default chunk, exactly 1000 rows' => [1000, [], 2],
    'default chunk, 1001 rows' => [1001, [], 2],
    'default chunk, 999 rows' => [999, [], 1],
    'chunk 2, 5 rows' => [5, ['--chunk' => 2], 3],
    'chunk 0 reads as 1' => [3, ['--chunk' => '0'], 4],
    'unusable chunk reads as 1000' => [3, ['--chunk' => 'many'], 1],
    'unusable chunk, 999 rows' => [999, ['--chunk' => 'many'], 1],
    'unusable chunk, 1000 rows' => [1000, ['--chunk' => 'many'], 2],
]);
