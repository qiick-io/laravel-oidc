<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Qiick\Oidc\Data\LogoutTokenData;
use Qiick\Oidc\Erasure\OidcEraser;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Models\OidcLogoutRevocation;
use Qiick\Oidc\Models\UserIdentity;
use Qiick\Oidc\Services\SessionRevocationService;

it('erases a public-ID match and its corroborated SID while preserving other issuers and owners', function (): void {
    Config::set('cache.stores.oidc-erasure', ['driver' => 'array']);
    Config::set('oidc.cache.store', ' oidc-erasure ');
    $user = localUser();
    $otherUser = localUser('other-erasure@example.test');
    $identity = linkIdentity($user, 'erasure-subject', 'https://first.example.test');
    $otherIdentity = linkIdentity($otherUser, 'another-subject', $identity->issuer);
    $revoker = app(SessionRevocationService::class);

    $signedLogout = new LogoutTokenData($identity->issuer, $identity->subject, 'corroborated-sid', 'replay-token');
    $revoker->revoke($signedLogout);
    $revoker->revoke(new LogoutTokenData($identity->issuer, null, 'corroborated-sid', null, channel: 'frontchannel'));
    $revoker->revoke(new LogoutTokenData($identity->issuer, null, 'uncorroborated-sid'));
    $revoker->revoke(new LogoutTokenData('https://second.example.test', null, 'corroborated-sid'));
    $revoker->revoke(new LogoutTokenData($identity->issuer, $otherIdentity->subject, 'other-sid'));

    $eraser = app(OidcEraser::class);
    $arguments = [(string) $user->id, (string) Str::uuid(), OidcEraser::DELETE];
    $report = $eraser->erase((string) ($otherUser->id + 100), $arguments[1], $arguments[2], [$identity->public_id]);

    expect($report->stores['user_identities'])->toBe(['deleted' => 1, 'anonymised' => 0, 'kept' => 0, 'reason' => null])
        ->and($report->stores['oidc_logout_revocations'])->toBe(['deleted' => 1, 'anonymised' => 1, 'kept' => 1, 'reason' => 'security_log'])
        ->and($report->stores['cleartext:oidc_logout_revocations.sid']['kept'])->toBe(1)
        ->and($report->stores['cache:oidc-erasure'])->toBe(['deleted' => 1, 'anonymised' => 0, 'kept' => 1, 'reason' => 'cache_ttl'])
        ->and($report->changed())->toBe(4)
        ->and(OidcLogoutRevocation::query()->count())->toBe(4)
        ->and(OidcLogoutRevocation::query()->whereNull('sid')->sole()->only(['sub', 'sid', 'jti']))
        ->toBe(['sub' => null, 'sid' => null, 'jti' => null])
        ->and($user->fresh())->not->toBeNull()
        ->and(UserIdentity::query()->sole()->public_id)->toBe($otherIdentity->public_id)
        ->and($eraser->erase(...$arguments)->changed())->toBe(0);

    $cache = Cache::store('oidc-erasure');
    expect($cache->has(SessionRevocationService::cacheKey('sid', $identity->issuer, 'corroborated-sid')))->toBeFalse()
        ->and($cache->has(SessionRevocationService::cacheKey('sid', $identity->issuer, 'uncorroborated-sid')))->toBeTrue()
        ->and($cache->has(SessionRevocationService::cacheKey('sid', 'https://second.example.test', 'corroborated-sid')))->toBeTrue()
        ->and($cache->has(SessionRevocationService::cacheKey('sid', $identity->issuer, 'other-sid')))->toBeTrue()
        ->and(fn () => $revoker->revoke($signedLogout))->toThrow(InvalidTokenException::class, 'logout_token [jti] was already used.');
});

it('reports a kept cache entry when competing subjects corroborate the same cached SID', function (bool $hasSessionOnlyRow, bool $hasCachedEntry): void {
    $user = localUser();
    $identity = linkIdentity($user);
    $revoker = app(SessionRevocationService::class);
    $revoker->revoke(new LogoutTokenData($identity->issuer, $identity->subject, 'shared-sid'));
    $revoker->revoke(new LogoutTokenData($identity->issuer, 'a-different-subject', 'shared-sid'));

    if ($hasSessionOnlyRow) {
        $revoker->revoke(new LogoutTokenData($identity->issuer, null, 'shared-sid'));
    }

    $cacheKey = SessionRevocationService::cacheKey('sid', $identity->issuer, 'shared-sid');

    if (! $hasCachedEntry) {
        Cache::forget($cacheKey);
    }

    $report = app(OidcEraser::class)->erase((string) $user->id, (string) Str::uuid(), OidcEraser::DELETE);

    expect($report->stores['cleartext:oidc_logout_revocations.sid']['kept'])->toBe($hasSessionOnlyRow ? 1 : 0)
        ->and($report->stores['cache:'.Cache::getDefaultDriver()])->toBe([
            'deleted' => 0,
            'anonymised' => 0,
            'kept' => $hasCachedEntry ? 1 : 0,
            'reason' => $hasCachedEntry ? 'cache_ttl' : null,
        ])
        ->and(OidcLogoutRevocation::query()->orderBy('id')->pluck('sub')->all())->toBe($hasSessionOnlyRow ? ['a-different-subject', null] : ['a-different-subject'])
        ->and(Cache::has($cacheKey))->toBe($hasCachedEntry);
})->with([
    'with a session-only row' => [true, true],
    'without a session-only row' => [false, true],
    'with an evicted cache entry' => [true, false],
]);

it('preserves the anonymised identity and revocation rows without any link back to the user', function (): void {
    $user = localUser();
    $identity = linkIdentity($user);
    app(SessionRevocationService::class)->revoke(new LogoutTokenData($identity->issuer, $identity->subject, null));

    $report = app(OidcEraser::class)->erase((string) $user->id, (string) Str::uuid(), OidcEraser::ANONYMISE);

    expect($report->stores['user_identities'])->toBe(['deleted' => 0, 'anonymised' => 1, 'kept' => 0, 'reason' => null])
        ->and($report->stores['oidc_logout_revocations'])->toBe(['deleted' => 0, 'anonymised' => 1, 'kept' => 0, 'reason' => null])
        ->and(OidcLogoutRevocation::query()->sole()->sub)->toBeNull()
        ->and($identity->fresh()->issuer)->toBe('erased')
        ->and($identity->fresh()->public_id)->not->toBe($identity->public_id)
        ->and($identity->fresh()->user_id)->toBeNull()
        ->and($user->fresh())->not->toBeNull();
});

it('clears the front-channel replay key when anonymising a corroborated SID', function (): void {
    $user = localUser();
    $identity = linkIdentity($user);
    $revoker = app(SessionRevocationService::class);
    $revoker->revoke(new LogoutTokenData($identity->issuer, $identity->subject, 'corroborated-sid', 'signed-token'));
    $revoker->revoke(new LogoutTokenData($identity->issuer, null, 'corroborated-sid', channel: 'frontchannel'));
    $frontChannelRevocation = OidcLogoutRevocation::query()->where('channel', 'frontchannel');

    expect($frontChannelRevocation->sole()->replay_key)->not->toBeNull();

    app(OidcEraser::class)->erase((string) $user->id, (string) Str::uuid(), OidcEraser::ANONYMISE);

    expect($frontChannelRevocation->sole()->only(['sid', 'replay_key']))->toBe(['sid' => null, 'replay_key' => null]);
});

it('scrubs database error messages and rolls back erasure writes', function (): void {
    $user = localUser();
    $identity = linkIdentity($user);
    app(SessionRevocationService::class)->revoke(new LogoutTokenData($identity->issuer, $identity->subject, null));

    DB::connection()->beforeExecuting(function (string $statement) use ($identity): void {
        if (str_starts_with(strtolower($statement), 'delete') && str_contains($statement, 'user_identities')) {
            throw new QueryException('testing', 'select ?', [$identity->subject], new RuntimeException('Erasure fault.'));
        }
    });

    expect(fn () => app(OidcEraser::class)->erase((string) $user->id, (string) Str::uuid(), OidcEraser::DELETE))
        ->toThrow(RuntimeException::class, 'OIDC erasure database operation failed.')
        ->and($identity->fresh())->not->toBeNull()
        ->and(OidcLogoutRevocation::query()->sole()->sub)->toBe($identity->subject)
        ->and(Cache::has(SessionRevocationService::cacheKey('sub', $identity->issuer, $identity->subject)))->toBeTrue();
});

it('rejects noncanonical user keys before a database can coerce them', function (string $userKey): void {
    $identity = linkIdentity(localUser());

    expect(fn () => app(OidcEraser::class)->erase($userKey, (string) Str::uuid(), OidcEraser::DELETE))
        ->toThrow(InvalidArgumentException::class, 'The OIDC user key must be a decimal integer.')
        ->and($identity->fresh())->not->toBeNull();
})->with(['1-not-a-user-key', '0001', '9223372036854775808']);
