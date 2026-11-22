<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Qiick\Oidc\Data\IdentitySessionData;
use Qiick\Oidc\Models\OidcLogoutRevocation;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Testing\FakeIdentityProvider;

/*
 * S3: front-channel logout behind oidc.frontchannel_logout.enabled (default off).
 * S4: oidc.routes.except skips selected named routes.
 */

beforeEach(function (): void {
    $this->identityProvider = FakeIdentityProvider::fake();
    Route::middleware('web')->get('/probe', fn () => auth()->check() ? 'signed-in' : 'guest');
});

it('answers 404 for front-channel logout while the flag is off', function (): void {
    $this->get('/auth/oidc/frontchannel-logout?iss='.urlencode($this->identityProvider->issuer).'&sid=s1')
        ->assertNotFound();
});

it('revokes the IdP session from iss and sid when front-channel logout is on', function (): void {
    Config::set('oidc.frontchannel_logout.enabled', true);
    $issuer = $this->identityProvider->issuer;

    $this->get('/auth/oidc/frontchannel-logout?iss='.urlencode($issuer).'&sid=front-sid-1')
        ->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertHeader('Content-Security-Policy', 'frame-ancestors https://idp.example.com');

    $row = OidcLogoutRevocation::query()->sole();

    expect($row->channel)->toBe('frontchannel')
        ->and($row->sid)->toBe('front-sid-1')
        ->and($row->jti)->toBeNull();

    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession([IdentitySessionService::SESSION_KEY => (new IdentitySessionData(
            issuer: $issuer,
            subject: 'user-1',
            sessionId: 'front-sid-1',
            idToken: 'header.payload.signature',
            authenticatedAt: Date::now()->getTimestamp(),
        ))->toArray()])
        ->get('/probe')
        ->assertSeeText('guest');
});

it('refuses front-channel logout without both iss and sid', function (string $query): void {
    Config::set('oidc.frontchannel_logout.enabled', true);

    $this->get('/auth/oidc/frontchannel-logout'.$query)->assertStatus(400);
})->with([
    'missing both' => [''],
    'iss only' => ['?iss=https://idp.example.com/realms/test'],
    'sid only' => ['?sid=s1'],
]);

it('refuses a front-channel iss that is not the configured issuer', function (): void {
    Config::set('oidc.frontchannel_logout.enabled', true);

    $this->get('/auth/oidc/frontchannel-logout?iss='.urlencode('https://evil.example.com').'&sid=s1')
        ->assertStatus(400);
});
