<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Event;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Data\IdentitySessionData;
use Qiick\Oidc\Data\ProviderConfigurationData;
use Qiick\Oidc\Events\OidcLogoutReceivedEvent;
use Qiick\Oidc\Exceptions\OidcNotConfiguredException;
use Qiick\Oidc\Http\Controllers\FrontChannelLogoutController;
use Qiick\Oidc\Models\OidcLogoutRevocation;
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
        ->assertContent('')
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertHeader('Content-Security-Policy', 'frame-ancestors https://idp.example.com');

    $row = OidcLogoutRevocation::query()->sole();

    expect($row->channel)->toBe('frontchannel')
        ->and($row->sid)->toBe('front-sid-1')
        ->and($row->jti)->toBeNull();

    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession(storedSsoSession(new IdentitySessionData(
            issuer: $issuer,
            subject: 'user-1',
            sessionId: 'front-sid-1',
            idToken: 'header.payload.signature',
            authenticatedAt: Date::now()->getTimestamp(),
        )))
        ->get('/probe')
        ->assertSeeText('guest');
});

it('acknowledges a repeated front-channel logout without extending it or dispatching another event', function (): void {
    Event::fake([OidcLogoutReceivedEvent::class]);
    Config::set('oidc.frontchannel_logout.enabled', true);
    $logoutUrl = '/auth/oidc/frontchannel-logout?'.http_build_query(['iss' => $this->identityProvider->issuer, 'sid' => 'front-sid-1']);

    $this->get($logoutUrl)->assertOk();
    $originalExpiry = OidcLogoutRevocation::query()->sole()->expires_at;

    $this->travel(1)->seconds();
    $this->get($logoutUrl)->assertOk()->assertHeader('Cache-Control', 'no-store, private');

    $revocation = OidcLogoutRevocation::query()->sole();
    expect($revocation->replay_key)->not->toBeNull()
        ->and($revocation->expires_at->equalTo($originalExpiry))->toBeTrue();
    Event::assertDispatchedTimes(OidcLogoutReceivedEvent::class, 1);
});

it('keeps front-channel SID keys separate from signed back-channel JTI keys', function (): void {
    Config::set('oidc.frontchannel_logout.enabled', true);
    $sessionId = 'front-sid-1';

    $this->get('/auth/oidc/frontchannel-logout?'.http_build_query(['iss' => $this->identityProvider->issuer, 'sid' => $sessionId]))->assertOk();
    $this->post('/auth/oidc/backchannel-logout', [
        'logout_token' => $this->identityProvider->sign($this->identityProvider->logoutTokenClaims(['jti' => $sessionId]), ['typ' => 'logout+jwt']),
    ])->assertOk();

    expect(OidcLogoutRevocation::query()->distinct()->count('replay_key'))->toBe(2);
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

it('refuses a sid that does not fit the revocation table', function (): void {
    Config::set('oidc.frontchannel_logout.enabled', true);
    $this->get('/auth/oidc/frontchannel-logout?'.http_build_query(['iss' => $this->identityProvider->issuer, 'sid' => str_repeat('a', 256)]))
        ->assertStatus(400);

    $this->get('/auth/oidc/frontchannel-logout?'.http_build_query(['iss' => $this->identityProvider->issuer, 'sid' => str_repeat('a', 255)]))
        ->assertOk();
});

it('refuses empty, list-shaped or padded iss and sid, without caching the error', function (string $query): void {
    Config::set('oidc.frontchannel_logout.enabled', true);
    $issuer = urlencode($this->identityProvider->issuer);

    $this->get('/auth/oidc/frontchannel-logout?'.str_replace('{issuer}', $issuer, $query))
        ->assertStatus(400)
        ->assertHeader('Cache-Control', 'no-store, private');

    expect(OidcLogoutRevocation::query()->count())->toBe(0);
})->with([
    'empty iss' => ['iss=&sid=s1'],
    'empty sid' => ['iss={issuer}&sid='],
    'iss as a list' => ['iss[]={issuer}&sid=s1'],
    'sid as a list' => ['iss={issuer}&sid[]=s1'],
]);

it('refuses empty or padded values even in an app without the TrimStrings middleware', function (?string $issuer, string $sessionId, string $error): void {
    Config::set('oidc.frontchannel_logout.enabled', true);
    // Called directly: Laravel's global TrimStrings and ConvertEmptyStringsToNull would otherwise clean the query first.
    $request = Request::create('/auth/oidc/frontchannel-logout', 'GET', ['iss' => $issuer ?? $this->identityProvider->issuer, 'sid' => $sessionId]);

    $response = app()->call(FrontChannelLogoutController::class, ['request' => $request]);

    expect($response->getStatusCode())->toBe(400)
        ->and($response->getContent())->toBe($error);
})->with([
    'padded sid' => [null, ' s1', 'Front-channel logout [sid] has leading or trailing whitespace.'],
    'empty sid' => [null, '', 'Front-channel logout requires both [iss] and [sid].'],
    'empty iss' => ['', 's1', 'Front-channel logout requires both [iss] and [sid].'],
]);

it('lets only the issuer origin frame the endpoint', function (string $issuer, string $frameAncestors): void {
    Config::set(['oidc.frontchannel_logout.enabled' => true, 'oidc.issuer' => $issuer]);

    $this->get('/auth/oidc/frontchannel-logout?'.http_build_query(['iss' => $issuer, 'sid' => 's1']))
        ->assertOk()
        ->assertHeader('Content-Security-Policy', 'frame-ancestors '.$frameAncestors);
})->with([
    'with a port' => ['https://idp.example.com:8443/realms/test', 'https://idp.example.com:8443'],
    'not a URL' => ['urn:example:idp', "'none'"],
]);

it('answers 400, not 500, when the app repository is enabled but cannot build its configuration', function (): void {
    Config::set('oidc.frontchannel_logout.enabled', true);
    app()->bind(ProviderConfigurationRepositoryContract::class, fn (): ProviderConfigurationRepositoryContract => new class implements ProviderConfigurationRepositoryContract
    {
        public function isEnabled(): bool
        {
            return true;
        }

        public function configuration(): ProviderConfigurationData
        {
            throw new OidcNotConfiguredException('The settings row is incomplete.');
        }
    });

    $this->get('/auth/oidc/frontchannel-logout?iss='.urlencode($this->identityProvider->issuer).'&sid=front-sid-1')
        ->assertStatus(400)
        ->assertContent('Front-channel logout is not configured.');

    expect(OidcLogoutRevocation::query()->count())->toBe(0);
});
