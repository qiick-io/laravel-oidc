<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Exceptions\InvalidCallbackException;
use Qiick\Oidc\Http\Middleware\EnsureOidcSessionIsActiveMiddleware;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Services\OidcLoginService;
use Qiick\Oidc\Testing\FakeIdentityProvider;
use Symfony\Component\HttpFoundation\Response;

/*
 * The edges of the package's HTTP surface: session fixation on login, the
 * session check without a session or with a token guard, and the redirect,
 * callback and back-channel controllers' small branches.
 */

it('gives the browser a new session id when SSO signs it in', function (): void {
    linkIdentity(localUser());
    $identityProvider = fakeProvider();
    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->headers->get('Location');
    $sessionIdBeforeLogin = session()->getId();

    $this->get($identityProvider->authorize($authorizationUrl))->assertRedirect('/');

    expect(session()->getId())->not->toBe($sessionIdBeforeLogin);
});

it('refuses to sign in on a default guard that keeps no session', function (): void {
    linkIdentity(localUser());
    Config::set('auth.guards.token', ['driver' => 'token', 'provider' => 'users']);
    Config::set('auth.defaults.guard', 'token');
    $identity = completeLogin(fakeProvider());
    $request = browserRequest('http://localhost/auth/oidc/callback', browserSession());

    app(OidcLoginService::class)->login($request, $identity);
})->throws(LogicException::class, 'SSO login needs a stateful (session) guard as the default guard.');

it('lets a request without a session through untouched', function (): void {
    $response = app(EnsureOidcSessionIsActiveMiddleware::class)->handle(Request::create('/api/ping'), fn (): Response => new Response('passed'));

    expect($response->getContent())->toBe('passed');
});

it('ends a revoked session with a new id and CSRF token', function (): void {
    FakeIdentityProvider::fake();
    Route::middleware('web')->get('/probe', fn () => auth()->check() ? 'signed-in' : 'guest');
    $session = browserSession();
    $session->put(IdentitySessionService::SESSION_KEY, 'unreadable');
    $sessionIdBefore = $session->getId();
    $tokenBefore = $session->token();
    $request = Request::create('/probe');
    $request->setLaravelSession($session);

    app(EnsureOidcSessionIsActiveMiddleware::class)->handle($request, fn (): Response => new Response('passed'));

    expect($session->getId())->not->toBe($sessionIdBefore)
        ->and($session->token())->toBeString()->toHaveLength(40)->not->toBe($tokenBefore)
        ->and($session->has(IdentitySessionService::SESSION_KEY))->toBeFalse();
});

it('ends a revoked session on a default guard that keeps no session', function (): void {
    FakeIdentityProvider::fake();
    Config::set('auth.guards.token', ['driver' => 'token', 'provider' => 'users']);
    Config::set('auth.defaults.guard', 'token');
    $session = browserSession();
    $session->put(IdentitySessionService::SESSION_KEY, 'unreadable');
    $request = Request::create('/probe');
    $request->setLaravelSession($session);

    $response = app(EnsureOidcSessionIsActiveMiddleware::class)->handle($request, fn (): Response => new Response('passed'));

    expect($response->getContent())->toBe('passed')
        ->and($session->has(IdentitySessionService::SESSION_KEY))->toBeFalse();
});

it('asks the IdP for acr_values only when the configured value is a non-empty string', function (mixed $requestAcrValues): void {
    fakeProvider(['mfa.request_acr_values' => $requestAcrValues]);

    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->headers->get('Location');

    expect(queryParameters($authorizationUrl))->not->toHaveKey('acr_values');
})->with(['empty' => [''], 'not a string' => [['gold']], 'unset' => [null]]);

it('refuses an empty logout_token and logs why a logout was refused', function (): void {
    FakeIdentityProvider::fake();
    Log::spy();
    // An app may drop ConvertEmptyStringsToNull: the empty token must still
    // be refused before any discovery fetch.
    $this->withoutMiddleware(ConvertEmptyStringsToNull::class);

    $this->post('/auth/oidc/backchannel-logout', ['logout_token' => ''])
        ->assertStatus(400)
        ->assertJson(['error' => 'invalid_request', 'error_description' => 'Missing logout_token.']);

    Http::assertNothingSent();

    $this->post('/auth/oidc/backchannel-logout', ['logout_token' => 'not.a.jwt'])->assertStatus(400);

    Log::shouldHaveReceived('warning')->withArgs(fn (string $message): bool => $message === 'OIDC back-channel logout refused: Token header is not valid JSON.');
});

it('answers an accepted back-channel logout with an empty body', function (): void {
    $identityProvider = FakeIdentityProvider::fake();

    $this->post('/auth/oidc/backchannel-logout', [
        'logout_token' => $identityProvider->sign($identityProvider->logoutTokenClaims(), ['typ' => 'logout+jwt']),
    ])->assertOk()->assertContent('');
});

it('logs the exception class of a failed callback, never only its message', function (): void {
    FakeIdentityProvider::fake();
    Log::spy();
    $this->get('/auth/oidc/redirect');

    $this->get('/auth/oidc/callback?code=stolen&state=forged')->assertRedirect('/login');

    Log::shouldHaveReceived('warning')->withArgs(
        fn (string $message, array $context): bool => str_starts_with($message, 'OIDC login failed: ')
            && $context === ['exception' => InvalidCallbackException::class],
    );
});
