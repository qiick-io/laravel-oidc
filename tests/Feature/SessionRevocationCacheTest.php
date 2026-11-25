<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Date;
use Qiick\Oidc\Data\IdentitySessionData;
use Qiick\Oidc\Data\LogoutTokenData;
use Qiick\Oidc\Models\OidcLogoutRevocation;
use Qiick\Oidc\Services\SessionRevocationService;
use Qiick\Oidc\Testing\FakeIdentityProvider;

/*
 * The cache in front of oidc_logout_revocations (standards review M10): it
 * may only answer "revoked", it is warmed on write and on a table hit, and
 * it never outlives the row it mirrors. Deleting the rows after a revocation
 * shows what the cache alone answers.
 */

const CACHE_TEST_ISSUER = 'https://idp.example.com/realms/test';

beforeEach(function (): void {
    FakeIdentityProvider::fake();
    Date::setTestNow('2026-11-23 12:00:00');
});

function cachedSession(?string $sessionId, string $subject = 'fake-subject-1', ?int $authenticatedAt = null): IdentitySessionData
{
    return new IdentitySessionData(
        issuer: CACHE_TEST_ISSUER,
        subject: $subject,
        sessionId: $sessionId,
        idToken: 'header.payload.signature',
        authenticatedAt: $authenticatedAt ?? Date::now()->subMinute()->getTimestamp(),
    );
}

function revokeForCacheTest(?string $sessionId, ?string $subject, string $tokenId): void
{
    app(SessionRevocationService::class)->revoke(new LogoutTokenData(
        issuer: CACHE_TEST_ISSUER,
        subject: $subject,
        sessionId: $sessionId,
        tokenId: $tokenId,
        expiresAt: Date::now()->addMinutes(2)->getTimestamp(),
    ));
}

function isCachedSessionRevoked(IdentitySessionData $identity): bool
{
    return app(SessionRevocationService::class)->isRevoked($identity);
}

it('answers from the cache it warmed on write until the row expires', function (?string $sessionId, ?string $subject): void {
    $session = cachedSession($sessionId);
    revokeForCacheTest($sessionId, $subject, 'jti-write');
    $expiresAt = OidcLogoutRevocation::query()->sole()->expires_at;
    OidcLogoutRevocation::query()->delete();

    expect(isCachedSessionRevoked($session))->toBeTrue();

    Date::setTestNow($expiresAt->subSecond());
    expect(isCachedSessionRevoked($session))->toBeTrue();

    Date::setTestNow($expiresAt);
    expect(isCachedSessionRevoked($session))->toBeFalse();
})->with([
    'sid' => ['fake-session-1', null],
    'sub only' => [null, 'fake-subject-1'],
]);

it('re-warms the cache from a table hit, until the row expires', function (?string $sessionId, ?string $subject): void {
    $session = cachedSession($sessionId);
    revokeForCacheTest($sessionId, $subject, 'jti-read');
    $expiresAt = OidcLogoutRevocation::query()->sole()->expires_at;
    Cache::flush();

    expect(isCachedSessionRevoked($session))->toBeTrue();

    OidcLogoutRevocation::query()->delete();

    expect(isCachedSessionRevoked($session))->toBeTrue();

    Date::setTestNow($expiresAt);
    expect(isCachedSessionRevoked($session))->toBeFalse();
})->with([
    'sid' => ['fake-session-1', null],
    'sub only' => [null, 'fake-subject-1'],
]);

it('keeps the sub cut-off in the cache: later sessions of the user stay signed in', function (): void {
    revokeForCacheTest(null, 'fake-subject-1', 'jti-cut-off');
    OidcLogoutRevocation::query()->delete();

    expect(isCachedSessionRevoked(cachedSession(null, authenticatedAt: Date::now()->getTimestamp())))->toBeTrue()
        ->and(isCachedSessionRevoked(cachedSession(null, authenticatedAt: Date::now()->addSecond()->getTimestamp())))->toBeFalse();
});

it('keeps a sid and a sub with the same value apart in the cache', function (): void {
    revokeForCacheTest(null, 'shared-value', 'jti-sub-shared');
    OidcLogoutRevocation::query()->delete();

    expect(isCachedSessionRevoked(cachedSession('shared-value', subject: 'another-subject')))->toBeFalse();
});

it('keeps the cache entries of two sessions of one issuer apart', function (): void {
    revokeForCacheTest('session-a', null, 'jti-a');
    OidcLogoutRevocation::query()->delete();

    expect(isCachedSessionRevoked(cachedSession('session-a')))->toBeTrue()
        ->and(isCachedSessionRevoked(cachedSession('session-b')))->toBeFalse();
});

it('keeps the cache entries of one session id at two issuers apart', function (): void {
    revokeForCacheTest('fake-session-1', null, 'jti-issuer');
    OidcLogoutRevocation::query()->delete();

    $otherIssuerSession = new IdentitySessionData(
        issuer: 'https://other-idp.example.com',
        subject: 'fake-subject-1',
        sessionId: 'fake-session-1',
        idToken: 'header.payload.signature',
        authenticatedAt: Date::now()->subMinute()->getTimestamp(),
    );

    expect(isCachedSessionRevoked($otherIssuerSession))->toBeFalse();
});
