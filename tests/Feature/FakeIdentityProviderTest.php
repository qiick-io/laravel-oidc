<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Http;
use Qiick\Oidc\Testing\FakeIdentityProvider;

/*
 * The fake IdP ships to apps, so it must behave like a strict IdP: these
 * tests pin its token, userinfo and JWKS endpoints and its authorization
 * checks directly, without the package's client in between.
 */

const FAKE_REDIRECT_URI = 'https://app.example.com/auth/oidc/callback';

/**
 * A valid authorization URL for the fake, with $overrides applied to its
 * query (null removes a parameter).
 *
 * @param  array<string, string|null>  $overrides
 */
function fakeAuthorizationUrl(FakeIdentityProvider $identityProvider, string $codeVerifier, array $overrides = [], ?string $endpoint = null): string
{
    $parameters = array_filter([
        'response_type' => 'code',
        'client_id' => $identityProvider->clientId,
        'redirect_uri' => FAKE_REDIRECT_URI,
        'scope' => 'openid email',
        'state' => 'state-1',
        'nonce' => 'nonce-1',
        'code_challenge' => JWT::urlsafeB64Encode(hash('sha256', $codeVerifier, true)),
        'code_challenge_method' => 'S256',
        ...$overrides,
    ], fn (?string $value): bool => $value !== null);

    return ($endpoint ?? $identityProvider->issuer.'/protocol/openid-connect/auth').'?'.http_build_query($parameters);
}

/**
 * The code from a callback URL the fake built.
 */
function codeFrom(string $callbackUrl): string
{
    parse_str((string) parse_url($callbackUrl, PHP_URL_QUERY), $query);

    return is_string($query['code'] ?? null) ? $query['code'] : '';
}

/**
 * @param  array<string, string>  $form
 */
function postToken(FakeIdentityProvider $identityProvider, array $form, ?string $basicCredentials = null): Response
{
    $request = Http::asForm();

    if ($basicCredentials !== null) {
        $request = $request->withHeaders(['Authorization' => 'Basic '.base64_encode($basicCredentials)]);
    }

    return $request->post($identityProvider->issuer.'/protocol/openid-connect/token', $form);
}

/**
 * @return array<string, string>
 */
function tokenForm(string $code, string $codeVerifier, array $overrides = []): array
{
    return [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => FAKE_REDIRECT_URI,
        'code_verifier' => $codeVerifier,
        'client_id' => 'laravel-app',
        'client_secret' => 'fake-client-secret',
        ...$overrides,
    ];
}

beforeEach(function (): void {
    $this->identityProvider = FakeIdentityProvider::fake();
    $this->codeVerifier = str_repeat('v', 43);
});

it('returns the callback URL with a fresh code and the state', function (): void {
    $callbackUrl = $this->identityProvider->authorize(fakeAuthorizationUrl($this->identityProvider, $this->codeVerifier));

    expect($callbackUrl)->toStartWith(FAKE_REDIRECT_URI.'?code=')
        ->and($callbackUrl)->toEndWith('&state=state-1')
        ->and(codeFrom($callbackUrl))->toMatch('/^[0-9a-f]{32}$/');
});

it('refuses an authorization request a strict IdP would refuse', function (array $overrides, ?string $endpoint, string $requirement): void {
    $this->identityProvider->authorize(fakeAuthorizationUrl($this->identityProvider, $this->codeVerifier, $overrides, $endpoint));
})->throws(RuntimeException::class)->with([
    'other endpoint' => [[], 'https://idp.example.com/realms/test/protocol/openid-connect/other', 'authorization endpoint'],
    'endpoint without a query' => [[], 'https://idp.example.com/realms/test/protocol/openid-connect/authorize', 'authorization endpoint'],
    'implicit flow' => [['response_type' => 'token'], null, 'response_type=code'],
    'other client' => [['client_id' => 'other-app'], null, 'client_id'],
    'plain PKCE' => [['code_challenge_method' => 'plain'], null, 'code_challenge_method=S256'],
    'no challenge' => [['code_challenge' => null], null, 'code_challenge'],
    'no redirect URI' => [['redirect_uri' => null], null, 'redirect_uri'],
    'no openid scope' => [['scope' => 'email'], null, 'openid scope'],
]);

it('names the requirement an authorization request breaks', function (): void {
    expect(fn () => $this->identityProvider->authorize(fakeAuthorizationUrl($this->identityProvider, $this->codeVerifier, ['scope' => 'email'])))
        ->toThrow(RuntimeException::class, 'FakeIdentityProvider: the authorization request has an invalid openid scope.');
});

it('exchanges a code once, with the PKCE verifier and the registered redirect URI', function (): void {
    $code = codeFrom($this->identityProvider->authorize(
        fakeAuthorizationUrl($this->identityProvider, $this->codeVerifier),
        ['sub' => 'user-42', 'locale' => 'it'],
        ['phone_number' => '+0000'],
    ));

    $tokenResponse = postToken($this->identityProvider, tokenForm($code, $this->codeVerifier));
    $idTokenClaims = json_decode(JWT::urlsafeB64Decode(explode('.', $tokenResponse->json('id_token'))[1]), true);

    expect($tokenResponse->status())->toBe(200)
        ->and($tokenResponse->json('token_type'))->toBe('Bearer')
        ->and($tokenResponse->json('expires_in'))->toBe(300)
        ->and($tokenResponse->json('access_token'))->toMatch('/^[0-9a-f]{32}$/')
        ->and($idTokenClaims['nonce'])->toBe('nonce-1')
        ->and($idTokenClaims['sub'])->toBe('user-42')
        ->and($this->identityProvider->tokenRequestCount)->toBe(1);

    $userinfoResponse = Http::withToken($tokenResponse->json('access_token'))->get($this->identityProvider->issuer.'/protocol/openid-connect/userinfo');

    expect($userinfoResponse->json())->toBe([
        'sub' => 'user-42',
        'email' => 'sso.user@example.com',
        'email_verified' => true,
        'name' => 'Sso User',
        'given_name' => 'Sso',
        'family_name' => 'User',
        'phone_number' => '+0000',
    ])->and($this->identityProvider->userinfoRequestCount)->toBe(1)
        ->and(postToken($this->identityProvider, tokenForm($code, $this->codeVerifier))->json())->toBe(['error' => 'invalid_grant'])
        ->and($this->identityProvider->tokenRequestCount)->toBe(2);
});

it('issues no nonce when the authorization request had none', function (): void {
    $code = codeFrom($this->identityProvider->authorize(fakeAuthorizationUrl($this->identityProvider, $this->codeVerifier, ['nonce' => null])));

    $idToken = postToken($this->identityProvider, tokenForm($code, $this->codeVerifier))->json('id_token');

    expect(json_decode(JWT::urlsafeB64Decode(explode('.', $idToken)[1]), true))->not->toHaveKey('nonce');
});

it('refuses a code exchange a strict IdP would refuse', function (array $overrides, int $status, string $error): void {
    $code = codeFrom($this->identityProvider->authorize(fakeAuthorizationUrl($this->identityProvider, $this->codeVerifier)));

    $response = postToken($this->identityProvider, array_filter(tokenForm($code, $this->codeVerifier, $overrides), fn (?string $value): bool => $value !== null));

    expect([$response->status(), $response->json()])->toBe([$status, ['error' => $error]]);
})->with([
    'wrong secret' => [['client_secret' => 'wrong'], 401, 'invalid_client'],
    'other client' => [['client_id' => 'other-app'], 401, 'invalid_client'],
    'unknown code' => [['code' => 'unknown'], 400, 'invalid_grant'],
    'no code' => [['code' => null], 400, 'invalid_grant'],
    'other grant type' => [['grant_type' => 'refresh_token'], 400, 'invalid_grant'],
    'other redirect URI' => [['redirect_uri' => 'https://evil.example.com/cb'], 400, 'invalid_grant'],
    'wrong verifier' => [['code_verifier' => str_repeat('w', 43)], 400, 'invalid_grant'],
    'no verifier' => [['code_verifier' => null], 400, 'invalid_grant'],
]);

it('authenticates a confidential client with HTTP Basic only when the header matches', function (string $credentials, int $status): void {
    $code = codeFrom($this->identityProvider->authorize(fakeAuthorizationUrl($this->identityProvider, $this->codeVerifier)));
    $form = tokenForm($code, $this->codeVerifier);
    unset($form['client_id'], $form['client_secret']);

    expect(postToken($this->identityProvider, $form, $credentials)->status())->toBe($status);
})->with([
    'matching' => ['laravel-app:fake-client-secret', 200],
    'wrong secret' => ['laravel-app:wrong', 401],
]);

it('authenticates a public client by client_id alone and refuses a secret', function (?string $clientSecret, int $status): void {
    // Another issuer, so the public fake answers instead of the one from beforeEach.
    $identityProvider = FakeIdentityProvider::fake(issuer: 'https://public-idp.example.com/realms/test', clientSecret: null);
    $code = codeFrom($identityProvider->authorize(fakeAuthorizationUrl($identityProvider, $this->codeVerifier)));

    $form = tokenForm($code, $this->codeVerifier, ['client_secret' => $clientSecret]);

    expect(postToken($identityProvider, array_filter($form, fn (?string $value): bool => $value !== null))->status())->toBe($status);
})->with([
    'no secret' => [null, 200],
    'with a secret' => ['anything', 401],
]);

it('refuses userinfo without a valid bearer token', function (array $headers): void {
    $response = Http::withHeaders($headers)->get($this->identityProvider->issuer.'/protocol/openid-connect/userinfo');

    expect([$response->status(), $response->json()])->toBe([401, ['error' => 'invalid_token']]);
})->with([
    'no header' => [[]],
    'unknown token' => [['Authorization' => 'Bearer unknown']],
    'not a bearer token' => [['Authorization' => 'Basic abc']],
]);

it('accepts an issued access token only as a bearer token', function (): void {
    $code = codeFrom($this->identityProvider->authorize(fakeAuthorizationUrl($this->identityProvider, $this->codeVerifier)));
    $accessToken = postToken($this->identityProvider, tokenForm($code, $this->codeVerifier))->json('access_token');

    $response = Http::withHeaders(['Authorization' => 'Token '.$accessToken])->get($this->identityProvider->issuer.'/protocol/openid-connect/userinfo');

    expect($response->status())->toBe(401);
});

it('answers 404 on any other path', function (): void {
    $response = Http::get($this->identityProvider->issuer.'/unknown');

    expect([$response->status(), $response->json()])->toBe([404, ['error' => 'not_found']]);
});

it('counts discovery and JWKS requests from zero', function (): void {
    expect([$this->identityProvider->discoveryRequestCount, $this->identityProvider->jwksRequestCount, $this->identityProvider->tokenRequestCount, $this->identityProvider->userinfoRequestCount])
        ->toBe([0, 0, 0, 0]);

    Http::get($this->identityProvider->issuer.'/.well-known/openid-configuration');
    Http::get($this->identityProvider->issuer.'/protocol/openid-connect/certs');

    expect([$this->identityProvider->discoveryRequestCount, $this->identityProvider->jwksRequestCount])->toBe([1, 1]);
});

it('keeps every discovery override and removes a field set to null', function (): void {
    $this->identityProvider->withDiscovery(['end_session_endpoint' => null])->withDiscovery(['acr_values_supported' => ['gold']]);

    expect($this->identityProvider->discoveryDocument())->not->toHaveKey('end_session_endpoint')
        ->and($this->identityProvider->discoveryDocument()['acr_values_supported'])->toBe(['gold']);
});

it('builds id_token and logout_token claims valid for five and two minutes', function (): void {
    Date::setTestNow('2026-11-23 12:00:00');
    $now = Date::now()->getTimestamp();

    $idTokenClaims = $this->identityProvider->idTokenClaims();
    $logoutTokenClaims = $this->identityProvider->logoutTokenClaims(['sid' => null]);

    expect([$idTokenClaims['iat'], $idTokenClaims['exp'], $idTokenClaims['auth_time']])->toBe([$now, $now + 300, $now])
        ->and([$logoutTokenClaims['iat'], $logoutTokenClaims['exp']])->toBe([$now, $now + 120])
        ->and($logoutTokenClaims['jti'])->toMatch('/^[0-9a-f]{16}$/')
        ->and($logoutTokenClaims)->not->toHaveKey('sid')
        ->and($logoutTokenClaims['sub'])->toBe('fake-subject-1');
});

it('publishes every signing key, of any type, for verification', function (): void {
    $this->identityProvider->rotateSigningKey(keyType: 'EC');
    $this->identityProvider->rotateSigningKey();

    $publishedKeys = $this->identityProvider->jwks()['keys'];

    expect(array_column($publishedKeys, 'kty'))->toBe(['RSA', 'EC', 'RSA'])
        ->and(array_unique(array_column($publishedKeys, 'use')))->toBe(['sig'])
        ->and(array_column($publishedKeys, 'alg'))->toBe(['ES256']);
});

it('pads EC coordinates that OpenSSL returns without their leading zero byte', function (): void {
    $hasPaddedX = false;
    $hasPaddedY = false;

    // About one key in 256 has a coordinate starting with a zero byte.
    for ($attempt = 0; $attempt < 5000 && ! ($hasPaddedX && $hasPaddedY); $attempt++) {
        $this->identityProvider->rotateSigningKey(isPreviousKeyRetired: true, keyType: 'EC');
        $publishedKey = $this->identityProvider->jwks()['keys'][0];
        $curveX = JWT::urlsafeB64Decode($publishedKey['x']);
        $curveY = JWT::urlsafeB64Decode($publishedKey['y']);

        expect([strlen($curveX), strlen($curveY)])->toBe([32, 32]);
        $hasPaddedX = $hasPaddedX || $curveX[0] === "\0";
        $hasPaddedY = $hasPaddedY || $curveY[0] === "\0";
    }

    expect([$hasPaddedX, $hasPaddedY])->toBe([true, true]);
});
