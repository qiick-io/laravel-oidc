<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Enums\LoginRefusalReasonEnum;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Services\AuthorizationCodeFlowService;
use Qiick\Oidc\Testing\FakeIdentityProvider;
use Qiick\Oidc\Tests\Support\User;

/**
 * @param  array<string, mixed>  $claims
 * @param  array<string, mixed>  $userinfoClaims
 */
function loginWithUserinfo(FakeIdentityProvider $identityProvider, array $claims = [], array $userinfoClaims = []): AuthenticatedIdentityData
{
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session), $claims, $userinfoClaims);

    return app(AuthorizationCodeFlowService::class)->handleCallback(browserRequest($callbackUrl, $session));
}

it('adds the userinfo claims, with the signed id_token winning conflicts', function (): void {
    $identityProvider = FakeIdentityProvider::fake();

    $identity = loginWithUserinfo($identityProvider, ['email' => 'signed@example.com'], [
        'email' => 'unsigned@example.com',
        'picture' => 'https://idp.example.com/avatar.png',
        'orgs' => [['id' => 'org-1', 'slug' => 'acme', 'roles' => ['admin']]],
    ]);

    expect($identity->claim('email'))->toBe('signed@example.com')
        ->and($identity->claim('picture'))->toBe('https://idp.example.com/avatar.png')
        ->and($identity->claim('orgs'))->toBe([['id' => 'org-1', 'slug' => 'acme', 'roles' => ['admin']]])
        ->and($identityProvider->userinfoRequestCount)->toBe(1);
});

it('refuses a userinfo response for another subject', function (): void {
    loginWithUserinfo(FakeIdentityProvider::fake(), [], ['sub' => 'someone-else']);
})->throws(InvalidTokenException::class, 'Userinfo [sub]');

it('skips userinfo when turned off or when the IdP has no endpoint', function (array $configOverrides, array $discoveryOverrides): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: $configOverrides)->withDiscovery($discoveryOverrides);

    expect(loginWithUserinfo($identityProvider, [], ['picture' => 'x'])->claim('picture'))->toBeNull()
        ->and($identityProvider->userinfoRequestCount)->toBe(0);
})->with([
    'turned off' => [['userinfo' => false], []],
    'no endpoint' => [[], ['userinfo_endpoint' => null]],
]);

it('never takes a trust-sensitive claim from userinfo, even when the id_token lacks it', function (string $claim, mixed $userinfoValue): void {
    $identityProvider = FakeIdentityProvider::fake();

    // Re-sign the id_token without the claim at all (not even as null), so
    // only the filter keeps the userinfo value out.
    $identityProvider->modifyTokenResponseUsing(function (array $tokenResponse) use ($identityProvider, $claim): array {
        $idTokenClaims = json_decode(JWT::urlsafeB64Decode(explode('.', $tokenResponse['id_token'])[1]), true);
        unset($idTokenClaims[$claim]);

        return [...$tokenResponse, 'id_token' => $identityProvider->sign($idTokenClaims)];
    });

    $identity = loginWithUserinfo($identityProvider, userinfoClaims: [$claim => $userinfoValue]);

    expect($identity->claims)->not->toHaveKey($claim);
})->with([
    'amr' => ['amr', ['mfa']],
    'acr' => ['acr', 'urn:qiick:loa:mfa'],
    'auth_time' => ['auth_time', 1],
    'sid' => ['sid', 'userinfo-session'],
    'azp' => ['azp', 'laravel-app'],
    'nbf' => ['nbf', 1],
]);

/**
 * The fake IdP's id_token without $claims at all, as an IdP that releases
 * profile and email claims at userinfo only (OIDC Core 5.4, issue #64).
 *
 * @param  list<string>  $claims
 */
function withoutIdTokenClaims(FakeIdentityProvider $identityProvider, array $claims): void
{
    $identityProvider->modifyTokenResponseUsing(function (array $tokenResponse) use ($identityProvider, $claims): array {
        $idTokenClaims = json_decode(JWT::urlsafeB64Decode(explode('.', $tokenResponse['id_token'])[1]), true);

        return [...$tokenResponse, 'id_token' => $identityProvider->sign(array_diff_key($idTokenClaims, array_flip($claims)))];
    });
}

it('provisions a user from the email and names released at userinfo only', function (): void {
    $identityProvider = fakeProvider(['jit' => true]);
    withoutIdTokenClaims($identityProvider, ['email', 'email_verified', 'name', 'given_name', 'family_name']);
    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->headers->get('Location');

    $this->get($identityProvider->authorize($authorizationUrl, userinfoClaims: [
        'email' => 'grace@example.com',
        'email_verified' => true,
        'name' => null,
        'given_name' => 'Grace',
        'family_name' => 'Hopper',
    ]))->assertRedirect('/');

    expect(User::query()->sole()->only(['email', 'name']))->toBe(['email' => 'grace@example.com', 'name' => 'Grace Hopper']);
});

it('refuses with a clear reason when the IdP released no email and userinfo is off', function (): void {
    $identityProvider = fakeProvider(['jit' => true, 'userinfo' => false]);
    withoutIdTokenClaims($identityProvider, ['email', 'email_verified']);

    assertRefused(ssoLogin($this, $identityProvider), LoginRefusalReasonEnum::EmailNotReleased);
    expect(User::query()->count())->toBe(0);
});
