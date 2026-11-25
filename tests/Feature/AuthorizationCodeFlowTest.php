<?php

declare(strict_types=1);

use Illuminate\Cache\ArrayStore;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Http;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Exceptions\InvalidCallbackException;
use Qiick\Oidc\Exceptions\OidcNotConfiguredException;
use Qiick\Oidc\Services\AuthorizationCodeFlowService;
use Qiick\Oidc\Testing\FakeIdentityProvider;

function callback(string $callbackUrl, Session $session): AuthenticatedIdentityData
{
    return app(AuthorizationCodeFlowService::class)->handleCallback(browserRequest($callbackUrl, $session));
}

it('needs SSO to be configured', function (): void {
    startLogin(browserSession());
})->throws(OidcNotConfiguredException::class);

it('redirects with PKCE S256, state, nonce and the configured scopes', function (): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['scopes' => ['profile', 'email', 'qiick.orgs']]);

    $parameters = queryParameters(startLogin(browserSession()));

    expect($parameters)->toMatchArray([
        'response_type' => 'code',
        'client_id' => $identityProvider->clientId,
        'redirect_uri' => 'http://localhost/auth/oidc/callback',
        'scope' => 'openid profile email qiick.orgs',
        'code_challenge_method' => 'S256',
    ])
        ->and($parameters['state'])->toMatch('/^[A-Za-z0-9_-]{43}$/')
        ->and($parameters['nonce'])->toMatch('/^[A-Za-z0-9_-]{43}$/')
        ->and($parameters['code_challenge'])->toMatch('/^[A-Za-z0-9_-]{43}$/')
        ->and($parameters['state'])->not->toBe($parameters['nonce']);
});

it('passes optional parameters but never lets them override the protocol ones', function (): void {
    FakeIdentityProvider::fake();

    $parameters = queryParameters(startLogin(browserSession(), [
        'prompt' => 'login',
        'login_hint' => 'user@example.com',
        'state' => 'attacker-state',
        'code_challenge_method' => 'plain',
        'redirect_uri' => 'https://evil.example.com/',
    ]));

    expect($parameters['prompt'])->toBe('login')
        ->and($parameters['login_hint'])->toBe('user@example.com')
        ->and($parameters['state'])->not->toBe('attacker-state')
        ->and($parameters['code_challenge_method'])->toBe('S256')
        ->and($parameters['redirect_uri'])->toBe('http://localhost/auth/oidc/callback');
});

it('completes the login and returns the identity keyed by issuer and subject', function (): void {
    $identityProvider = FakeIdentityProvider::fake();

    $identity = completeLogin($identityProvider, ['sub' => 'user-42', 'email' => 'ada@example.com']);

    expect($identity->issuer)->toBe($identityProvider->issuer)
        ->and($identity->subject)->toBe('user-42')
        ->and($identity->claim('email'))->toBe('ada@example.com')
        ->and($identity->sessionId)->toBe('fake-session-1')
        ->and($identity->idToken)->toContain('.')
        ->and($identity->accessToken)->not->toBe('');
});

it('authenticates with client_secret_post and as a public client', function (array $configOverrides, ?string $clientSecret): void {
    $identityProvider = FakeIdentityProvider::fake(clientSecret: $clientSecret, configOverrides: $configOverrides);

    expect(completeLogin($identityProvider)->subject)->toBe('fake-subject-1');

    Http::assertSent(function (HttpRequest $request) use ($clientSecret): bool {
        if (! str_ends_with($request->url(), '/token')) {
            return false;
        }

        return ! $request->hasHeader('Authorization')
            && $request['client_id'] === 'laravel-app'
            && ($request->data()['client_secret'] ?? null) === $clientSecret;
    });
})->with([
    'client_secret_post' => [['token_endpoint_auth_method' => 'client_secret_post'], 'post-secret'],
    'public client' => [[], null],
]);

it('sends the PKCE verifier that matches the challenge', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $session = browserSession();
    $authorizationUrl = startLogin($session);
    $callbackUrl = $identityProvider->authorize($authorizationUrl);

    callback($callbackUrl, $session);

    Http::assertSent(fn (HttpRequest $request): bool => str_ends_with($request->url(), '/token')
        && is_string($request['code_verifier'])
        && strlen($request['code_verifier']) === 86
        && rtrim(strtr(base64_encode(hash('sha256', $request['code_verifier'], true)), '+/', '-_'), '=') === queryParameters($authorizationUrl)['code_challenge']);
});

it('refuses a callback without state, with an unknown state, or from another browser session', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $callbackUrl = $identityProvider->authorize(startLogin(browserSession()));
    $parameters = queryParameters($callbackUrl);

    expect(fn () => callback('http://localhost/auth/oidc/callback?code='.$parameters['code'], browserSession()))
        ->toThrow(InvalidCallbackException::class, 'state')
        ->and(fn () => callback('http://localhost/auth/oidc/callback?code=x&state=forged', browserSession()))
        ->toThrow(InvalidCallbackException::class, 'state')
        ->and(fn () => callback($callbackUrl, browserSession()))
        ->toThrow(InvalidCallbackException::class, 'state')
        ->and($identityProvider->tokenRequestCount)->toBe(0);
});

it('refuses a replay of a callback that succeeded', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));

    callback($callbackUrl, $session);

    expect(fn () => callback($callbackUrl, $session))->toThrow(InvalidCallbackException::class, 'The authorization response has a missing or unknown state.');
});

it('accepts each state once, even after a callback the IdP answered with an error', function (): void {
    // The parallel session copy still holds the pending login, so only the
    // used-state marker can refuse the replay.
    FakeIdentityProvider::fake();
    $session = browserSession();
    $state = queryParameters(startLogin($session))['state'];
    $parallelSession = clone $session;
    $deniedCallbackUrl = 'http://localhost/auth/oidc/callback?error=access_denied&state='.$state;

    expect(fn () => callback($deniedCallbackUrl, $session))->toThrow(InvalidCallbackException::class, 'access_denied')
        ->and(fn () => callback($deniedCallbackUrl, $parallelSession))->toThrow(InvalidCallbackException::class, 'state was already used');
});

it('accepts each state once across requests that read the session before either wrote it', function (): void {
    // Two parallel callbacks with one state each load the session before
    // either saves it, so both still hold the pending login.
    $identityProvider = FakeIdentityProvider::fake();
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));
    $parallelSession = clone $session;

    callback($callbackUrl, $session);

    expect(fn () => callback($callbackUrl, $parallelSession))->toThrow(InvalidCallbackException::class, 'state was already used')
        ->and($identityProvider->tokenRequestCount)->toBe(1);
});

it('refuses the callback when the state cannot be recorded as used', function (): void {
    Cache::extend('failing', fn (): CacheRepository => Cache::repository(new class extends ArrayStore
    {
        public function add($key, $value, $seconds): bool
        {
            throw new RuntimeException('Cache is down.');
        }
    }));
    config()->set('cache.stores.failing', ['driver' => 'failing']);
    config()->set('oidc.cache.store', 'failing');
    $identityProvider = FakeIdentityProvider::fake();
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));

    expect(fn () => callback($callbackUrl, $session))->toThrow(InvalidCallbackException::class, 'could not be recorded as used')
        ->and($identityProvider->tokenRequestCount)->toBe(0);
});

it('refuses the per-request array cache outside tests, since it cannot make a state single-use', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    config()->set('oidc.cache.store', 'array');
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));
    app()->detectEnvironment(fn (): string => 'production');

    expect(fn () => callback($callbackUrl, $session))->toThrow(InvalidCallbackException::class, 'array')
        ->and($identityProvider->tokenRequestCount)->toBe(0);
});

it('records the used state per issuer for as long as a pending login lives', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));

    callback($callbackUrl, $session);

    expect(Cache::get('oidc:state:'.hash('sha256', $identityProvider->issuer."\n".queryParameters($callbackUrl)['state'])))->toBeTrue();
});

it('accepts a shared cache store outside tests', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    config()->set('oidc.cache.store', 'database');
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));
    app()->detectEnvironment(fn (): string => 'production');

    expect(callback($callbackUrl, $session)->subject)->toBe('fake-subject-1');
});

it('keeps parallel logins from two tabs apart', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $session = browserSession();
    $firstCallbackUrl = $identityProvider->authorize(startLogin($session), ['sub' => 'first']);
    $secondCallbackUrl = $identityProvider->authorize(startLogin($session), ['sub' => 'second']);

    expect(callback($secondCallbackUrl, $session)->subject)->toBe('second')
        ->and(callback($firstCallbackUrl, $session)->subject)->toBe('first');
});

it('expires a pending login after ten minutes', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));

    Date::setTestNow(Date::now()->addSeconds(AuthorizationCodeFlowService::PENDING_LOGIN_SECONDS + 1));

    callback($callbackUrl, $session);
})->throws(InvalidCallbackException::class, 'too long');

it('reports an IdP error with its code only', function (): void {
    FakeIdentityProvider::fake();
    $session = browserSession();
    $state = queryParameters(startLogin($session))['state'];

    expect(fn () => callback("http://localhost/auth/oidc/callback?state={$state}&error=access_denied&error_description=%3Cscript%3E", $session))
        ->toThrow(InvalidCallbackException::class, 'The IdP refused the login (access_denied).');
});

it('refuses a callback without a code', function (): void {
    FakeIdentityProvider::fake();
    $session = browserSession();
    $state = queryParameters(startLogin($session))['state'];

    callback("http://localhost/auth/oidc/callback?state={$state}", $session);
})->throws(InvalidCallbackException::class, 'no code');

it('checks the RFC 9207 iss parameter', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));

    callback($callbackUrl.'&iss='.urlencode('https://evil.example.com'), $session);
})->throws(InvalidCallbackException::class, '[iss]');

it('requires the iss parameter when the IdP advertises it', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $identityProvider->withDiscovery(['authorization_response_iss_parameter_supported' => true]);
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));

    expect(fn () => callback($callbackUrl, $session))->toThrow(InvalidCallbackException::class, '[iss]');

    $callbackUrl = $identityProvider->authorize(startLogin($session));

    expect(callback($callbackUrl.'&iss='.urlencode($identityProvider->issuer), $session)->subject)->toBe('fake-subject-1');
});

it('refuses a callback when the settings changed during the login', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));

    config(['oidc.redirect_uri' => 'https://app.example.com/other-callback']);

    callback($callbackUrl, $session);
})->throws(InvalidCallbackException::class, 'settings changed');

it('surfaces a refused code exchange with the OAuth error code', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));
    $tamperedCallbackUrl = preg_replace('/code=[^&]+/', 'code=stolen-code', $callbackUrl);

    callback((string) $tamperedCallbackUrl, $session);
})->throws(IdentityProviderRequestException::class, 'HTTP 400 (invalid_grant)');

it('refuses a token response without an id_token', function (): void {
    $identityProvider = FakeIdentityProvider::fake()
        ->modifyTokenResponseUsing(fn (array $tokenResponse): array => ['access_token' => $tokenResponse['access_token'], 'token_type' => 'Bearer']);

    completeLogin($identityProvider);
})->throws(IdentityProviderRequestException::class, 'no id_token');

it('reports a malformed IdP error code as unknown', function (): void {
    FakeIdentityProvider::fake();
    $session = browserSession();
    $state = queryParameters(startLogin($session))['state'];

    expect(fn () => callback("http://localhost/auth/oidc/callback?state={$state}&error[]=access_denied", $session))
        ->toThrow(InvalidCallbackException::class, 'The IdP refused the login (unknown).');
});

it('refuses a callback with an empty code', function (): void {
    FakeIdentityProvider::fake();
    $session = browserSession();
    $state = queryParameters(startLogin($session))['state'];

    callback("http://localhost/auth/oidc/callback?state={$state}&code=", $session);
})->throws(InvalidCallbackException::class, 'no code');

it('reads an empty sid as no IdP session', function (): void {
    expect(completeLogin(FakeIdentityProvider::fake(), ['sid' => ''])->sessionId)->toBeNull();
});

it('refuses a pending login exactly when it expires', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    Date::setTestNow(Date::now()->startOfSecond());
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session));

    Date::setTestNow(Date::now()->addSeconds(600));

    callback($callbackUrl, $session);
})->throws(InvalidCallbackException::class, 'too long');

it('keeps only the five newest pending logins', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $session = browserSession();
    $callbackUrls = array_map(fn (): string => $identityProvider->authorize(startLogin($session)), range(1, 6));

    expect(fn () => callback($callbackUrls[0], $session))->toThrow(InvalidCallbackException::class, 'missing or unknown state')
        ->and(callback($callbackUrls[1], $session)->subject)->toBe('fake-subject-1');
});
