<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Data\IdentitySessionData;
use Qiick\Oidc\Services\IdentitySessionService;

/*
 * M4: session payload carries format_version; unknown versions fail closed.
 */

beforeEach(function (): void {
    Route::middleware('web')->get('/probe', fn () => auth()->check() ? 'signed-in' : 'guest');
});

it('writes format_version 1 with acr, amr and auth_time on login', function (): void {
    Date::setTestNow('2026-11-22 12:00:00');
    linkIdentity(localUser(), 'user-42');
    $authenticationTime = Date::now()->subMinute()->getTimestamp();

    ssoLogin($this, fakeProvider(), [
        'sub' => 'user-42',
        'auth_time' => $authenticationTime,
        'acr' => 'urn:mace:incommon:iap:silver',
        'amr' => ['pwd', 'mfa'],
    ])->assertRedirect('/');

    $sessionIdentity = app(IdentitySessionService::class)->current(session()->driver());

    expect($sessionIdentity)->not->toBeNull()
        ->and($sessionIdentity?->formatVersion)->toBe(1)
        ->and($sessionIdentity?->acr)->toBe('urn:mace:incommon:iap:silver')
        ->and($sessionIdentity?->amr)->toBe(['pwd', 'mfa'])
        ->and($sessionIdentity?->authTime)->toBe($authenticationTime);
});

it('reads a missing format_version as 1 for pre-M4 sessions', function (): void {
    $identity = IdentitySessionData::fromArray([
        'issuer' => 'https://idp.example.com/realms/test',
        'subject' => 'user-42',
        'session_id' => 'sid-1',
        'id_token' => 'header.payload.signature',
        'authenticated_at' => 1_700_000_000,
    ]);

    expect($identity)->not->toBeNull()
        ->and($identity?->formatVersion)->toBe(1);
});

it('refuses an unknown format_version', function (): void {
    expect(IdentitySessionData::fromArray([
        'issuer' => 'https://idp.example.com/realms/test',
        'subject' => 'user-42',
        'session_id' => 'sid-1',
        'id_token' => 'header.payload.signature',
        'authenticated_at' => 1_700_000_000,
        'format_version' => 99,
    ]))->toBeNull();
});

it('ends the local session when the stored identity has an unknown format_version', function (): void {
    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession([
            IdentitySessionService::SESSION_KEY => [
                'issuer' => 'https://idp.example.com/realms/test',
                'subject' => 'user-42',
                'session_id' => 'sid-1',
                'id_token' => 'header.payload.signature',
                'authenticated_at' => Date::now()->getTimestamp(),
                'format_version' => 99,
            ],
        ])
        ->get('/probe')
        ->assertSeeText('guest');
});
