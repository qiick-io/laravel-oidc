<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
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
    'maximum revocation lifetime' => [86_400, 120, 86_400],
    'maximum session lifetime' => [null, 1440, 86_400],
]);

it('refuses a revocation or session lifetime above 24 hours', function (string $key, int $value): void {
    Config::set($key, $value);

    expect(fn () => OidcLogoutRevocation::maximumConfiguredLifetimeSeconds())
        ->toThrow(InvalidArgumentException::class, 'OIDC logout revocation retention cannot exceed 24 hours.');
})->with([
    'revocation lifetime' => ['oidc.backchannel_logout.revocation_ttl', 86_401],
    'session lifetime' => ['session.lifetime', 1441],
]);

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
