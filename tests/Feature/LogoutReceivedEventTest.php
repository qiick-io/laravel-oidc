<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Testing\TestResponse;
use Qiick\Oidc\Events\OidcLogoutReceivedEvent;
use Qiick\Oidc\Testing\FakeIdentityProvider;

/*
 * S8: every stored OIDC logout raises OidcLogoutReceivedEvent, so a product
 * can write its activity log; a refused or replayed logout raises none.
 */

beforeEach(function (): void {
    Event::fake([OidcLogoutReceivedEvent::class]);
    $this->identityProvider = FakeIdentityProvider::fake(configOverrides: ['frontchannel_logout.enabled' => true]);
});

/**
 * @param  array<string, mixed>  $overrides
 */
function postSignedLogoutToken(FakeIdentityProvider $identityProvider, array $overrides = []): TestResponse
{
    return test()->post('/auth/oidc/backchannel-logout', [
        'logout_token' => $identityProvider->sign($identityProvider->logoutTokenClaims($overrides), ['typ' => 'logout+jwt']),
    ]);
}

it('reports a back-channel logout with the subject and a hash of the sid', function (): void {
    postSignedLogoutToken($this->identityProvider)->assertOk();

    Event::assertDispatchedTimes(OidcLogoutReceivedEvent::class, 1);
    Event::assertDispatched(OidcLogoutReceivedEvent::class, fn (OidcLogoutReceivedEvent $event): bool => $event->channel === 'backchannel'
        && $event->issuer === $this->identityProvider->issuer
        && $event->subject === 'fake-subject-1'
        && $event->sessionIdHash === hash('sha256', 'fake-session-1'));
});

it('reports a sub-only back-channel logout without a sid hash', function (): void {
    postSignedLogoutToken($this->identityProvider, ['sid' => null])->assertOk();

    Event::assertDispatched(OidcLogoutReceivedEvent::class, fn (OidcLogoutReceivedEvent $event): bool => $event->subject === 'fake-subject-1'
        && $event->sessionIdHash === null);
});

it('reports a front-channel logout without a subject', function (): void {
    $this->get('/auth/oidc/frontchannel-logout?'.http_build_query(['iss' => $this->identityProvider->issuer, 'sid' => 'fake-session-1']))->assertOk();

    Event::assertDispatched(OidcLogoutReceivedEvent::class, fn (OidcLogoutReceivedEvent $event): bool => $event->channel === 'frontchannel'
        && $event->issuer === $this->identityProvider->issuer
        && $event->subject === null
        && $event->sessionIdHash === hash('sha256', 'fake-session-1'));
});

it('reports nothing for a refused or replayed logout', function (): void {
    postSignedLogoutToken($this->identityProvider, ['aud' => 'other-app'])->assertStatus(400);
    $this->get('/auth/oidc/frontchannel-logout?'.http_build_query(['iss' => 'https://evil.example.com', 'sid' => 'fake-session-1']))->assertStatus(400);

    Event::assertNotDispatched(OidcLogoutReceivedEvent::class);

    postSignedLogoutToken($this->identityProvider, ['jti' => 'once'])->assertOk();
    postSignedLogoutToken($this->identityProvider, ['jti' => 'once'])->assertStatus(400);

    Event::assertDispatchedTimes(OidcLogoutReceivedEvent::class, 1);
});

it('never puts the raw sid in the event', function (): void {
    postSignedLogoutToken($this->identityProvider)->assertOk();

    Event::assertDispatched(OidcLogoutReceivedEvent::class, fn (OidcLogoutReceivedEvent $event): bool => ! str_contains(serialize($event), 'fake-session-1'));
});
