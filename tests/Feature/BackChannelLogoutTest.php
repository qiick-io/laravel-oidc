<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Qiick\Oidc\Data\IdentitySessionData;
use Qiick\Oidc\Http\Middleware\EnsureOidcSessionIsActiveMiddleware;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Testing\FakeIdentityProvider;
use Tests\TestCase;

beforeEach(function (): void {
    $this->identityProvider = FakeIdentityProvider::fake();

    Route::middleware('web')->get('/probe', fn () => auth()->check() ? 'signed-in' : 'guest');
    // A route behind `auth`: this is where the middleware priority list matters, because `auth`
    // is in that list and the package's session check has to be ordered ahead of it. The `/probe`
    // route above cannot catch an ordering bug, since `web` alone is never reordered.
    Route::middleware(['web', 'auth'])->get('/guarded', fn () => 'reached the controller');
    // `auth` redirects guests to the `login` route, which the package's test app does not define.
    Route::middleware('web')->get('/login', fn () => 'login')->name('login');
});

/**
 * @param  array<string, mixed>  $overrides
 */
function postLogoutToken(TestCase|Orchestra\Testbench\TestCase $testCase, FakeIdentityProvider $identityProvider, array $overrides = []): TestResponse
{
    return $testCase->post('/auth/oidc/backchannel-logout', [
        'logout_token' => $identityProvider->sign($identityProvider->logoutTokenClaims($overrides), ['typ' => 'logout+jwt']),
    ]);
}

/**
 * Session data of a user who signed in through SSO at the given time.
 *
 * @return array<string, mixed>
 */
function ssoSession(?string $sessionId = 'fake-session-1', string $subject = 'fake-subject-1', ?int $authenticatedAt = null): array
{
    return [IdentitySessionService::SESSION_KEY => (new IdentitySessionData(
        issuer: 'https://idp.example.com/realms/test',
        subject: $subject,
        sessionId: $sessionId,
        idToken: 'header.payload.signature',
        authenticatedAt: $authenticatedAt ?? Date::now()->getTimestamp(),
    ))->toArray()];
}

it('accepts a valid logout_token without session or CSRF token', function (): void {
    postLogoutToken($this, $this->identityProvider)
        ->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private');
});

it('ends the local session created by the logged-out IdP session on its next request', function (): void {
    postLogoutToken($this, $this->identityProvider, ['sid' => 'fake-session-1'])->assertOk();

    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession(ssoSession('fake-session-1'))
        ->get('/probe')
        ->assertSeeText('guest');
});

it('leaves other IdP sessions and local logins alone', function (array $sessionData): void {
    postLogoutToken($this, $this->identityProvider, ['sid' => 'fake-session-1'])->assertOk();

    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession($sessionData)
        ->get('/probe')
        ->assertSeeText('signed-in');
})->with([
    'other IdP session of the same user' => fn () => ssoSession('another-session'),
    'local login' => fn () => [],
]);

it('ends every session of the user created before a sub-only logout', function (): void {
    $loggedInBefore = Date::now()->getTimestamp() - 60;
    postLogoutToken($this, $this->identityProvider, ['sid' => null])->assertOk();

    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession(ssoSession('any-session', authenticatedAt: $loggedInBefore))
        ->get('/probe')
        ->assertSeeText('guest');

    Date::setTestNow(Date::now()->addMinute());

    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession(ssoSession('new-session'))
        ->get('/probe')
        ->assertSeeText('signed-in');
});

it('refuses invalid logout tokens with 400', function (array $overrides): void {
    postLogoutToken($this, $this->identityProvider, $overrides)
        ->assertStatus(400)
        ->assertJson(['error' => 'invalid_request'])
        ->assertHeader('Cache-Control', 'no-store, private');
})->with([
    'no events' => [['events' => null]],
    'other event' => [['events' => ['https://example.com/other-event' => new stdClass]]],
    'nonce present (an id_token)' => [['nonce' => 'abc']],
    'neither sub nor sid' => [['sub' => null, 'sid' => null]],
    'sub with a trailing space' => [['sub' => 'fake-subject-1 ']],
    'sub with a leading space' => [['sub' => ' fake-subject-1']],
    'no jti' => [['jti' => null]],
    'other audience' => [['aud' => 'other-app']],
    'other issuer' => [['iss' => 'https://evil.example.com']],
    'expired' => [['iat' => 1, 'exp' => 2]],
]);

it('refuses an id_token posted as a logout_token', function (): void {
    $this->post('/auth/oidc/backchannel-logout', [
        'logout_token' => $this->identityProvider->sign($this->identityProvider->idTokenClaims(['nonce' => 'n'])),
    ])->assertStatus(400);
});

it('refuses a forged signature and a missing token', function (): void {
    $foreignKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]) ?: null;
    $currentKeyId = $this->identityProvider->jwks()['keys'][0]['kid'];

    $this->post('/auth/oidc/backchannel-logout', [
        'logout_token' => $this->identityProvider->sign($this->identityProvider->logoutTokenClaims(), keyId: $currentKeyId, privateKey: $foreignKey),
    ])->assertStatus(400);

    $this->post('/auth/oidc/backchannel-logout')->assertStatus(400)->assertJson(['error_description' => 'Missing logout_token.']);
});

it('accepts each jti once', function (): void {
    $logoutToken = $this->identityProvider->sign($this->identityProvider->logoutTokenClaims(['jti' => 'only-once']));

    $this->post('/auth/oidc/backchannel-logout', ['logout_token' => $logoutToken])->assertOk();
    $this->post('/auth/oidc/backchannel-logout', ['logout_token' => $logoutToken])
        ->assertStatus(400)
        ->assertJson(['error_description' => 'logout_token [jti] was already used.']);
});

it('answers 404 while SSO is off', function (): void {
    Config::set('oidc.enabled', false);

    postLogoutToken($this, $this->identityProvider)->assertNotFound();
});

/**
 * Regression: the package appends its session check to the `web` group, but Laravel's priority
 * list pulls `auth` ahead of anything it does not list, so without an explicit position the first
 * request after a back-channel logout reached the controller authenticated.
 */
it('does not let a revoked session reach a route behind auth', function (): void {
    postLogoutToken($this, $this->identityProvider, ['sid' => 'fake-session-1'])->assertOk();

    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession(ssoSession('fake-session-1'))
        ->get('/guarded')
        ->assertRedirect('/login');
});

it('orders its session check after the session starts and before auth', function (): void {
    $priority = app(Kernel::class)->getMiddlewarePriority();

    $session = array_search(EnsureOidcSessionIsActiveMiddleware::class, $priority, true);
    $startSession = array_search(StartSession::class, $priority, true);
    $auth = array_search(AuthenticatesRequests::class, $priority, true);

    expect($session)->not->toBeFalse()
        ->and($startSession)->toBeLessThan($session)
        ->and($session)->toBeLessThan($auth);
});
