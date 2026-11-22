<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Qiick\Oidc\Data\IdentitySessionData;
use Qiick\Oidc\Data\LogoutTokenData;
use Qiick\Oidc\Models\OidcLogoutRevocation;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Services\SessionRevocationService;
use Qiick\Oidc\Testing\FakeIdentityProvider;

/*
 * M10 security core: durable oidc_logout_revocations.
 * - unique (issuer, jti) refuses replay
 * - cache miss never means "not revoked" (table answers)
 * - failed table read means revoked (fail closed)
 */

beforeEach(function (): void {
    $this->identityProvider = FakeIdentityProvider::fake();
    Route::middleware('web')->get('/probe', fn () => auth()->check() ? 'signed-in' : 'guest');
});

/**
 * @return array<string, mixed>
 */
function durableSsoSession(?string $sessionId = 'fake-session-1', string $subject = 'fake-subject-1', ?int $authenticatedAt = null): array
{
    return [IdentitySessionService::SESSION_KEY => (new IdentitySessionData(
        issuer: 'https://idp.example.com/realms/test',
        subject: $subject,
        sessionId: $sessionId,
        idToken: 'header.payload.signature',
        authenticatedAt: $authenticatedAt ?? Date::now()->getTimestamp(),
    ))->toArray()];
}

it('persists a back-channel logout in oidc_logout_revocations', function (): void {
    $this->post('/auth/oidc/backchannel-logout', [
        'logout_token' => $this->identityProvider->sign(
            $this->identityProvider->logoutTokenClaims(['sid' => 'fake-session-1', 'jti' => 'jti-one']),
            ['typ' => 'logout+jwt'],
        ),
    ])->assertOk();

    $row = OidcLogoutRevocation::query()->sole();

    expect($row->issuer)->toBe('https://idp.example.com/realms/test')
        ->and($row->sid)->toBe('fake-session-1')
        ->and($row->jti)->toBe('jti-one')
        ->and($row->channel)->toBe('backchannel');
});

it('refuses a replayed logout_token via the unique (issuer, jti) key', function (): void {
    $logoutToken = $this->identityProvider->sign(
        $this->identityProvider->logoutTokenClaims(['sid' => 'fake-session-1', 'jti' => 'jti-replay']),
        ['typ' => 'logout+jwt'],
    );

    $this->post('/auth/oidc/backchannel-logout', ['logout_token' => $logoutToken])->assertOk();

    // Drop the cache jti pre-check so only the table unique key can refuse the replay.
    Cache::flush();

    $this->post('/auth/oidc/backchannel-logout', ['logout_token' => $logoutToken])
        ->assertStatus(400);

    expect(OidcLogoutRevocation::query()->count())->toBe(1);
});

it('still revokes after a cache flush because only the table answers not-revoked', function (): void {
    $this->post('/auth/oidc/backchannel-logout', [
        'logout_token' => $this->identityProvider->sign(
            $this->identityProvider->logoutTokenClaims(['sid' => 'fake-session-1', 'jti' => 'jti-cache']),
            ['typ' => 'logout+jwt'],
        ),
    ])->assertOk();

    Cache::flush();

    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession(durableSsoSession('fake-session-1'))
        ->get('/probe')
        ->assertSeeText('guest');
});

it('treats a failed table read as revoked and never as a negative cache', function (): void {
    Log::spy();
    $identity = new IdentitySessionData(
        issuer: 'https://idp.example.com/realms/test',
        subject: 'fake-subject-1',
        sessionId: 'fake-session-1',
        idToken: 'header.payload.signature',
        authenticatedAt: Date::now()->getTimestamp(),
    );

    Schema::rename('oidc_logout_revocations', 'oidc_logout_revocations_hidden');

    try {
        expect(app(SessionRevocationService::class)->isRevoked($identity))->toBeTrue();
        Log::shouldHaveReceived('warning')->withArgs(
            fn (string $message): bool => str_contains($message, 'logout revocation table read failed'),
        );
    } finally {
        Schema::rename('oidc_logout_revocations_hidden', 'oidc_logout_revocations');
    }
});

it('does not treat a cold cache as proof of not-revoked when a sub-only row exists', function (): void {
    app(SessionRevocationService::class)->revoke(new LogoutTokenData(
        issuer: 'https://idp.example.com/realms/test',
        subject: 'fake-subject-1',
        sessionId: null,
        tokenId: 'jti-sub',
        expiresAt: Date::now()->addHour()->getTimestamp(),
        channel: 'backchannel',
    ));

    Cache::flush();

    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession(durableSsoSession(sessionId: 'any-sid', subject: 'fake-subject-1', authenticatedAt: Date::now()->subMinute()->getTimestamp()))
        ->get('/probe')
        ->assertSeeText('guest');
});

it('answers not-revoked only when the table has no matching live row', function (): void {
    $identity = new IdentitySessionData(
        issuer: 'https://idp.example.com/realms/test',
        subject: 'untouched-subject',
        sessionId: 'untouched-sid',
        idToken: 'header.payload.signature',
        authenticatedAt: Date::now()->getTimestamp(),
    );

    expect(app(SessionRevocationService::class)->isRevoked($identity))->toBeFalse();
});

it('keeps a session revoked from the cache alone after the table row is gone', function (string $mode): void {
    $service = app(SessionRevocationService::class);
    $cutOff = Date::now()->getTimestamp();

    if ($mode === 'sid') {
        $service->revoke(new LogoutTokenData(
            issuer: 'https://idp.example.com/realms/test',
            subject: null,
            sessionId: 'cache-only-sid',
            tokenId: 'jti-cache-only-sid',
            expiresAt: Date::now()->addHour()->getTimestamp(),
        ));
    } else {
        $service->revoke(new LogoutTokenData(
            issuer: 'https://idp.example.com/realms/test',
            subject: 'cache-only-subject',
            sessionId: null,
            tokenId: 'jti-cache-only-sub',
            expiresAt: Date::now()->addHour()->getTimestamp(),
        ));
    }

    OidcLogoutRevocation::query()->delete();

    expect($service->isRevoked(new IdentitySessionData(
        issuer: 'https://idp.example.com/realms/test',
        subject: $mode === 'sid' ? 'anyone' : 'cache-only-subject',
        sessionId: $mode === 'sid' ? 'cache-only-sid' : 'any-sid',
        idToken: 'header.payload.signature',
        authenticatedAt: $cutOff,
    )))->toBeTrue();
})->with(['sid', 'sub']);

it('revokes a subject session authenticated at the cut-off instant, not one after', function (bool $useCache): void {
    Date::setTestNow('2026-11-22 12:00:00');
    $cutOff = Date::now()->getTimestamp();

    $service = app(SessionRevocationService::class);
    $service->revoke(new LogoutTokenData(
        issuer: 'https://idp.example.com/realms/test',
        subject: 'cut-off-subject',
        sessionId: null,
        tokenId: 'jti-cut-off-'.($useCache ? 'cache' : 'table'),
        expiresAt: Date::now()->addHour()->getTimestamp(),
    ));

    if (! $useCache) {
        Cache::flush();
    } else {
        OidcLogoutRevocation::query()->delete();
    }

    expect($service->isRevoked(new IdentitySessionData(
        issuer: 'https://idp.example.com/realms/test',
        subject: 'cut-off-subject',
        sessionId: 'sid-a',
        idToken: 'header.payload.signature',
        authenticatedAt: $cutOff,
    )))->toBeTrue()
        ->and($service->isRevoked(new IdentitySessionData(
            issuer: 'https://idp.example.com/realms/test',
            subject: 'cut-off-subject',
            sessionId: 'sid-b',
            idToken: 'header.payload.signature',
            authenticatedAt: $cutOff + 1,
        )))->toBeFalse();
})->with([
    'via table' => false,
    'via cache' => true,
]);

it('sets expires_at to the later of revocation lifetime and token exp plus 120 seconds', function (int $revocationTtl, ?int $tokenSecondsFromNow, int $expectedOffsetFromNow): void {
    Date::setTestNow('2026-11-22 12:00:00');
    $receivedAt = Date::now()->getTimestamp();
    $tokenId = 'jti-ttl-'.$revocationTtl.'-'.($tokenSecondsFromNow ?? 'null');

    $service = new SessionRevocationService(Cache::store(), $revocationTtl);
    $service->revoke(new LogoutTokenData(
        issuer: 'https://idp.example.com/realms/test',
        subject: null,
        sessionId: 'ttl-sid-'.$tokenId,
        tokenId: $tokenId,
        expiresAt: $tokenSecondsFromNow === null ? null : $receivedAt + $tokenSecondsFromNow,
    ));

    expect(OidcLogoutRevocation::query()->where('jti', $tokenId)->sole()->expires_at->getTimestamp())
        ->toBe($receivedAt + $expectedOffsetFromNow);
})->with([
    'token window wins' => [60, 30, 150],
    'revocation lifetime wins' => [300, 30, 300],
    'null token exp uses revocation lifetime' => [180, null, 180],
]);

it('prunes expired logout revocation rows', function (): void {
    OidcLogoutRevocation::query()->create([
        'issuer' => 'https://idp.example.com/realms/test',
        'sid' => 'old',
        'sub' => null,
        'jti' => 'jti-old',
        'channel' => 'backchannel',
        'received_at' => Date::now()->subDay(),
        'expires_at' => Date::now()->subHour(),
    ]);
    OidcLogoutRevocation::query()->create([
        'issuer' => 'https://idp.example.com/realms/test',
        'sid' => 'live',
        'sub' => null,
        'jti' => 'jti-live',
        'channel' => 'backchannel',
        'received_at' => Date::now(),
        'expires_at' => Date::now()->addDay(),
    ]);

    $this->artisan('oidc:prune-logout-revocations')
        ->expectsOutputToContain('Deleted 1 expired logout revocation')
        ->assertSuccessful();

    expect(OidcLogoutRevocation::query()->sole()->jti)->toBe('jti-live');
});
