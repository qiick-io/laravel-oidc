<?php

declare(strict_types=1);

use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Services\BackChannelLogoutService;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Testing\FakeIdentityProvider;

/**
 * Fixtures that mirror signaculum-core `docs/oidc-profile.md` after S1
 * (qiick-io/signaculum-core#36). They keep L1 honest until the Signaculum e2e job (L2).
 */
it('accepts the Signaculum discovery fixture as a valid IdP profile', function (): void {
    /** @var array<string, mixed> $discovery */
    $discovery = json_decode(
        (string) file_get_contents(__DIR__.'/../Fixtures/signaculum/discovery.json'),
        true,
        flags: JSON_THROW_ON_ERROR,
    );

    FakeIdentityProvider::fake(
        issuer: 'https://id.example.test',
        clientId: 'signaculum-test-client',
    )->withDiscovery($discovery);

    $document = app(DiscoveryService::class)->discover(
        app(ProviderConfigurationRepositoryContract::class)->configuration(),
    );

    expect($document->issuer)->toBe('https://id.example.test')
        ->and($document->authorizationEndpoint)->toBe('https://id.example.test/oauth/authorize')
        ->and($document->endSessionEndpoint)->toBe('https://id.example.test/oauth/end-session')
        ->and($discovery['response_types_supported'])->toContain('code')
        ->and($discovery['code_challenge_methods_supported'])->toContain('S256')
        ->and($discovery['claims_supported'])->toContain('sid')
        ->and($discovery['claims_supported'])->toContain('amr')
        ->and($discovery['claims_supported'])->toContain('acr')
        ->and($discovery['acr_values_supported'])->toBe(['urn:qiick:loa:pwd', 'urn:qiick:loa:mfa'])
        ->and($discovery['backchannel_logout_supported'])->toBeTrue()
        ->and($discovery['backchannel_logout_session_supported'])->toBeTrue();
});

it('builds a Signaculum-shaped logout_token that back-channel logout accepts', function (): void {
    /** @var array<string, mixed> $fixtureClaims */
    $fixtureClaims = json_decode(
        (string) file_get_contents(__DIR__.'/../Fixtures/signaculum/logout-token-claims.json'),
        true,
        flags: JSON_THROW_ON_ERROR,
    );

    expect($fixtureClaims)->toHaveKeys(['iss', 'aud', 'iat', 'exp', 'jti', 'sub', 'sid', 'events'])
        ->and($fixtureClaims)->not->toHaveKey('nonce')
        ->and($fixtureClaims['events'])->toHaveKey(BackChannelLogoutService::LOGOUT_EVENT);

    $identityProvider = FakeIdentityProvider::fake(
        issuer: 'https://id.example.test',
        clientId: 'signaculum-test-client',
    );

    $now = time();
    $logoutToken = $identityProvider->sign(
        $identityProvider->logoutTokenClaims([
            'sub' => $fixtureClaims['sub'],
            'sid' => $fixtureClaims['sid'],
            'jti' => $fixtureClaims['jti'],
            'iat' => $now,
            'exp' => $now + 120,
            'events' => [BackChannelLogoutService::LOGOUT_EVENT => new stdClass],
        ]),
        ['typ' => 'logout+jwt'],
    );

    $this->post('/auth/oidc/backchannel-logout', ['logout_token' => $logoutToken])
        ->assertOk();
});
