<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Contracts\SecondFactorChallengeContract;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Services\RpInitiatedLogoutService;
use Symfony\Component\HttpFoundation\Response;

/*
 * Standards review S6: the id_token kept for RP-initiated logout is stored
 * encrypted with the app key, so a database session row never holds the raw
 * JWT. A payload that cannot be decrypted fails closed (M4).
 */

beforeEach(function (): void {
    Route::middleware('web')->get('/probe', fn () => auth()->check() ? 'signed-in' : 'guest');
});

/**
 * The raw id_token the fake IdP issued for the last login, from the identity
 * the app can read back.
 */
function rememberedIdToken(): string
{
    return (string) app(IdentitySessionService::class)->current(session()->driver())?->idToken;
}

it('stores the id_token encrypted and reads it back in clear', function (): void {
    Config::set('session.encrypt', false);
    linkIdentity(localUser(), 'user-42');
    ssoLogin($this, fakeProvider(), ['sub' => 'user-42'])->assertRedirect('/');

    $storedPayload = session(IdentitySessionService::SESSION_KEY);
    $idToken = rememberedIdToken();

    expect($idToken)->toStartWith('eyJ')
        ->and(substr_count($idToken, '.'))->toBe(2)
        ->and($storedPayload['format_version'])->toBe(2)
        ->and($storedPayload['id_token'])->not->toBe($idToken)
        ->and($storedPayload['id_token'])->not->toContain($idToken)
        ->and(Crypt::decryptString($storedPayload['id_token']))->toBe($idToken);
});

it('sends the decrypted id_token as id_token_hint on logout', function (): void {
    linkIdentity(localUser(), 'user-42');
    ssoLogin($this, fakeProvider(), ['sub' => 'user-42'])->assertRedirect('/');

    $endSessionUrl = (string) app(RpInitiatedLogoutService::class)->endSessionUrl(session()->driver());

    expect(queryParameters($endSessionUrl)['id_token_hint'])->toBe(rememberedIdToken());
});

it('keeps the pending identity encrypted through the app challenge', function (): void {
    app()->instance(SecondFactorChallengeContract::class, new class implements SecondFactorChallengeContract
    {
        public function isRequired(Model&Authenticatable $user): bool
        {
            return true;
        }

        public function challenge(Request $request, Model&Authenticatable $user, bool $shouldRemember): ?Response
        {
            return new RedirectResponse('/two-factor-challenge');
        }
    });
    $user = localUser();
    linkIdentity($user);
    ssoLogin($this, fakeProvider())->assertRedirect('/two-factor-challenge');

    $pendingIdToken = session(IdentitySessionService::PENDING_SESSION_KEY)['identity']['id_token'];

    Auth::login($user);

    expect(substr_count($pendingIdToken, '.'))->not->toBe(2)
        ->and(Crypt::decryptString($pendingIdToken))->toBe(rememberedIdToken())
        ->and(Crypt::decryptString(session(IdentitySessionService::SESSION_KEY)['id_token']))->toBe(rememberedIdToken());
});

it('ends a session whose stored id_token cannot be decrypted', function (mixed $storedIdToken): void {
    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession([IdentitySessionService::SESSION_KEY => [
            'issuer' => 'https://idp.example.com/realms/test',
            'subject' => 'user-42',
            'session_id' => 'sid-1',
            'id_token' => $storedIdToken,
            'authenticated_at' => time(),
            'format_version' => 2,
        ]])
        ->get('/probe')
        ->assertSeeText('guest');
})->with([
    'tampered ciphertext' => fn () => substr(Crypt::encryptString('header.payload.signature'), 0, -4).'AAAA',
    'raw JWT under version 2' => ['header.payload.signature'],
    'not a string' => [['header.payload.signature']],
]);

it('still reads a version 1 session written by beta.6 with the raw id_token', function (): void {
    $this->actingAs(new GenericUser(['id' => 1, 'remember_token' => null]))
        ->withSession([IdentitySessionService::SESSION_KEY => [
            'issuer' => 'https://idp.example.com/realms/test',
            'subject' => 'user-42',
            'session_id' => 'sid-1',
            'id_token' => 'header.payload.signature',
            'authenticated_at' => time(),
            'format_version' => 1,
        ]])
        ->get('/probe')
        ->assertSeeText('signed-in');

    expect(app(IdentitySessionService::class)->current(session()->driver())?->idToken)->toBe('header.payload.signature');
});

it('re-encrypts a version 1 pending identity from beta.6 when the challenge promotes it', function (): void {
    $session = session()->driver();
    $session->put(IdentitySessionService::PENDING_SESSION_KEY, [
        'user_id' => 7,
        'expires_at' => time() + 60,
        'identity' => [
            'issuer' => 'https://idp.example.com/realms/test',
            'subject' => 'user-42',
            'id_token' => 'header.payload.signature',
            'authenticated_at' => time(),
            'format_version' => 1,
        ],
    ]);

    app(IdentitySessionService::class)->promotePending($session, 7);
    $storedPayload = $session->get(IdentitySessionService::SESSION_KEY);

    expect($storedPayload['format_version'])->toBe(2)
        ->and(Crypt::decryptString($storedPayload['id_token']))->toBe('header.payload.signature')
        ->and(app(IdentitySessionService::class)->current($session)?->idToken)->toBe('header.payload.signature');
});

it('reads no identity from a version 2 payload whose id_token is not a string', function (): void {
    $session = session()->driver();
    $session->put(IdentitySessionService::SESSION_KEY, [
        'issuer' => 'https://idp.example.com/realms/test',
        'subject' => 'user-42',
        'id_token' => ['not', 'a', 'string'],
        'authenticated_at' => time(),
        'format_version' => 2,
    ]);

    expect(app(IdentitySessionService::class)->current($session))->toBeNull();
});

it('upgrades a version 1 session to version 2 the first time it is read', function (): void {
    $session = session()->driver();
    $session->put(IdentitySessionService::SESSION_KEY, [
        'issuer' => 'https://idp.example.com/realms/test',
        'subject' => 'user-42',
        'id_token' => 'header.payload.signature',
        'authenticated_at' => time(),
        'format_version' => 1,
    ]);

    app(IdentitySessionService::class)->current($session);
    $storedPayload = $session->get(IdentitySessionService::SESSION_KEY);

    expect($storedPayload['format_version'])->toBe(2)
        ->and(Crypt::decryptString($storedPayload['id_token']))->toBe('header.payload.signature');
});

it('ends the session when the pending identity no longer reads at promotion', function (): void {
    $session = session()->driver();
    $session->put(IdentitySessionService::PENDING_SESSION_KEY, [
        'user_id' => 7,
        'expires_at' => time() + 60,
        'identity' => [
            'issuer' => 'https://idp.example.com/realms/test',
            'subject' => 'user-42',
            'id_token' => 'encrypted-with-an-old-app-key',
            'authenticated_at' => time(),
            'format_version' => 2,
        ],
    ]);

    app(IdentitySessionService::class)->promotePending($session, 7);

    // A stored but unreadable identity is what makes the middleware end the session (M4).
    expect($session->has(IdentitySessionService::SESSION_KEY))->toBeTrue()
        ->and(app(IdentitySessionService::class)->current($session))->toBeNull();

    $this->actingAs(new GenericUser(['id' => 7, 'remember_token' => null]))
        ->withSession([IdentitySessionService::SESSION_KEY => $session->get(IdentitySessionService::SESSION_KEY)])
        ->get('/probe')
        ->assertSeeText('guest');
});
