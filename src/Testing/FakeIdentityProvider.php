<?php

declare(strict_types=1);

namespace Qiick\Oidc\Testing;

use Closure;
use Firebase\JWT\JWT;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Http;
use OpenSSLAsymmetricKey;
use Qiick\Oidc\Services\BackChannelLogoutService;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Services\RemoteUrlGuardService;
use RuntimeException;

/**
 * An in-memory OpenID Provider for tests, in this package and in the apps
 * that use it. It needs no network: discovery, JWKS and the token endpoint
 * are served through Http::fake(), and the browser step is a method call.
 *
 *     $identityProvider = FakeIdentityProvider::fake();
 *     $callbackUrl = $identityProvider->authorize($this->get('/auth/oidc/redirect')->headers->get('Location'));
 *     $this->get($callbackUrl);
 *
 * It behaves like a strict IdP: authorize() checks the client id, redirect URI
 * and PKCE challenge method; the token endpoint checks the code (one use), the
 * redirect URI, the PKCE verifier and the client secret. id_tokens are signed
 * RS256 with a key generated per instance, so nothing secret is committed.
 */
final class FakeIdentityProvider
{
    public int $discoveryRequestCount = 0;

    public int $jwksRequestCount = 0;

    public int $tokenRequestCount = 0;

    public int $userinfoRequestCount = 0;

    /**
     * Signing keys by `kid`. The newest one signs; older ones stay published
     * until removed, like an IdP during key rotation.
     *
     * @var array<string, OpenSSLAsymmetricKey>
     */
    private array $signingKeys = [];

    private string $currentKeyId = '';

    /**
     * @var array<string, array{redirect_uri: string, code_challenge: string, nonce: ?string, claims: array<string, mixed>, userinfo_claims: array<string, mixed>}>
     */
    private array $issuedCodes = [];

    /**
     * Userinfo responses by access token.
     *
     * @var array<string, array<string, mixed>>
     */
    private array $issuedAccessTokens = [];

    /**
     * @var array<string, mixed>
     */
    private array $discoveryOverrides = [];

    /**
     * @var (Closure(array<string, mixed>): array<string, mixed>)|null
     */
    private ?Closure $tokenResponseModifier = null;

    public function __construct(
        public readonly string $issuer = 'https://idp.example.com/realms/test',
        public readonly string $clientId = 'laravel-app',
        public readonly ?string $clientSecret = 'fake-client-secret',
    ) {
        $this->rotateSigningKey();
    }

    /**
     * Creates the fake, serves it through Http::fake(), points `config('oidc')`
     * at it and lets the SSRF guard resolve its host to a public address.
     *
     * @param  array<string, mixed>  $configOverrides  extra `oidc.*` config keys (without the prefix)
     */
    public static function fake(
        string $issuer = 'https://idp.example.com/realms/test',
        string $clientId = 'laravel-app',
        ?string $clientSecret = 'fake-client-secret',
        array $configOverrides = [],
    ): self {
        $identityProvider = new self($issuer, $clientId, $clientSecret);

        Config::set('oidc.enabled', true);
        Config::set('oidc.issuer', $issuer);
        Config::set('oidc.client_id', $clientId);
        Config::set('oidc.client_secret', $clientSecret);

        foreach ($configOverrides as $key => $value) {
            Config::set("oidc.{$key}", $value);
        }

        app()->instance(RemoteUrlGuardService::class, new RemoteUrlGuardService(
            isPrivateHostAllowed: false,
            hostResolver: fn (string $host): array => ['93.184.215.14'],
        ));

        Http::fake([$identityProvider->baseUrl().'/*' => fn (HttpRequest $request): PromiseInterface => $identityProvider->handle($request)]);

        return $identityProvider;
    }

    public function baseUrl(): string
    {
        $scheme = parse_url($this->issuer, PHP_URL_SCHEME);
        $host = parse_url($this->issuer, PHP_URL_HOST);

        return "{$scheme}://{$host}";
    }

    /**
     * Plays the browser step: validates the authorization request and returns
     * the redirect URI with `code` and `state`, as the IdP would after login.
     *
     * @param  array<string, mixed>  $claims  id_token claims for this login (overrides the defaults)
     * @param  array<string, mixed>  $userinfoClaims  userinfo claims for this login, on top of the id_token's `sub` and profile claims
     */
    public function authorize(string $authorizationUrl, array $claims = [], array $userinfoClaims = []): string
    {
        parse_str((string) parse_url($authorizationUrl, PHP_URL_QUERY), $parameters);
        $redirectUri = $this->stringParameter($parameters, 'redirect_uri');
        $codeChallenge = $this->stringParameter($parameters, 'code_challenge');

        $this->expect(str_starts_with($authorizationUrl, $this->issuer.'/protocol/openid-connect/auth?'), 'authorization endpoint');
        $this->expect($this->stringParameter($parameters, 'response_type') === 'code', 'response_type=code');
        $this->expect($this->stringParameter($parameters, 'client_id') === $this->clientId, 'client_id');
        $this->expect($this->stringParameter($parameters, 'code_challenge_method') === 'S256', 'code_challenge_method=S256');
        $this->expect($codeChallenge !== null, 'code_challenge');
        $this->expect($redirectUri !== null, 'redirect_uri');
        $this->expect(in_array('openid', explode(' ', (string) $this->stringParameter($parameters, 'scope')), true), 'openid scope');

        $code = bin2hex(random_bytes(16));
        $this->issuedCodes[$code] = [
            'redirect_uri' => (string) $redirectUri,
            'code_challenge' => (string) $codeChallenge,
            'nonce' => $this->stringParameter($parameters, 'nonce'),
            'claims' => $claims,
            'userinfo_claims' => $userinfoClaims,
        ];

        return $redirectUri.'?'.http_build_query(['code' => $code, 'state' => $this->stringParameter($parameters, 'state')]);
    }

    /**
     * Signs arbitrary claims, for tests of tokens the IdP should never issue.
     * Signs with the current key unless $keyId or $privateKey says otherwise.
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, string|list<string>>  $header  extra JOSE header fields
     */
    public function sign(
        array $claims,
        array $header = [],
        ?string $keyId = null,
        ?OpenSSLAsymmetricKey $privateKey = null,
        bool $isKeyIdOmitted = false,
    ): string {
        $keyId ??= $this->currentKeyId;
        $privateKey ??= $this->signingKeys[$keyId];

        return JWT::encode($claims, $privateKey, 'RS256', $isKeyIdOmitted ? null : $keyId, $header);
    }

    /**
     * Valid id_token claims for this client; override any of them.
     *
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    public function idTokenClaims(array $overrides = []): array
    {
        $now = Date::now()->getTimestamp();

        return [
            'iss' => $this->issuer,
            'sub' => 'fake-subject-1',
            'aud' => $this->clientId,
            'iat' => $now,
            'exp' => $now + 300,
            'auth_time' => $now,
            'sid' => 'fake-session-1',
            'email' => 'sso.user@example.com',
            'email_verified' => true,
            'name' => 'Sso User',
            ...$overrides,
        ];
    }

    /**
     * Valid back-channel logout_token claims for this client (Back-Channel
     * Logout 1.0, 2.4); sign them with sign() and POST them to the app.
     *
     * @param  array<string, mixed>  $overrides  null removes a claim
     * @return array<string, mixed>
     */
    public function logoutTokenClaims(array $overrides = []): array
    {
        $now = Date::now()->getTimestamp();
        $claims = [
            'iss' => $this->issuer,
            'aud' => $this->clientId,
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => bin2hex(random_bytes(8)),
            'sub' => 'fake-subject-1',
            'sid' => 'fake-session-1',
            'events' => [BackChannelLogoutService::LOGOUT_EVENT => new \stdClass],
            ...$overrides,
        ];

        return array_filter($claims, fn (mixed $value): bool => $value !== null);
    }

    /**
     * Starts signing with a new key and `kid`. The previous key stays in the
     * JWKS unless $isPreviousKeyRetired is true.
     */
    public function rotateSigningKey(bool $isPreviousKeyRetired = false): string
    {
        if ($isPreviousKeyRetired) {
            unset($this->signingKeys[$this->currentKeyId]);
        }

        $privateKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        if ($privateKey === false) {
            throw new RuntimeException('OpenSSL could not generate a test key.');
        }

        $this->currentKeyId = 'fake-key-'.bin2hex(random_bytes(4));
        $this->signingKeys[$this->currentKeyId] = $privateKey;

        return $this->currentKeyId;
    }

    /**
     * @param  array<string, mixed>  $overrides  discovery fields to change or add; null removes a field
     */
    public function withDiscovery(array $overrides): self
    {
        $this->discoveryOverrides = [...$this->discoveryOverrides, ...$overrides];

        return $this;
    }

    /**
     * Lets a test change the token response, for example to send a forged id_token.
     *
     * @param  Closure(array<string, mixed>): array<string, mixed>  $modifier
     */
    public function modifyTokenResponseUsing(Closure $modifier): self
    {
        $this->tokenResponseModifier = $modifier;

        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function discoveryDocument(): array
    {
        $document = [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->issuer.'/protocol/openid-connect/auth',
            'token_endpoint' => $this->issuer.'/protocol/openid-connect/token',
            'userinfo_endpoint' => $this->issuer.'/protocol/openid-connect/userinfo',
            'jwks_uri' => $this->issuer.'/protocol/openid-connect/certs',
            'end_session_endpoint' => $this->issuer.'/protocol/openid-connect/logout',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
            ...$this->discoveryOverrides,
        ];

        return array_filter($document, fn (mixed $value): bool => $value !== null);
    }

    /**
     * @return array{keys: list<array<string, string>>}
     */
    public function jwks(): array
    {
        $publishedKeys = [];

        foreach ($this->signingKeys as $keyId => $privateKey) {
            $details = openssl_pkey_get_details($privateKey);

            $rsaDetails = is_array($details) && is_array($details['rsa'] ?? null) ? $details['rsa'] : [];
            $modulus = $rsaDetails['n'] ?? null;
            $exponent = $rsaDetails['e'] ?? null;

            if (! is_string($modulus) || ! is_string($exponent)) {
                throw new RuntimeException('OpenSSL could not read a test key.');
            }

            $publishedKeys[] = [
                'kty' => 'RSA',
                'use' => 'sig',
                'alg' => 'RS256',
                'kid' => $keyId,
                'n' => JWT::urlsafeB64Encode($modulus),
                'e' => JWT::urlsafeB64Encode($exponent),
            ];
        }

        return ['keys' => $publishedKeys];
    }

    private function handle(HttpRequest $request): PromiseInterface
    {
        $path = (string) parse_url($request->url(), PHP_URL_PATH);
        $issuerPath = (string) parse_url($this->issuer, PHP_URL_PATH);

        if ($path === $issuerPath.DiscoveryService::WELL_KNOWN_PATH) {
            $this->discoveryRequestCount++;

            return Http::response($this->discoveryDocument());
        }

        if ($path === $issuerPath.'/protocol/openid-connect/certs') {
            $this->jwksRequestCount++;

            return Http::response($this->jwks());
        }

        if ($path === $issuerPath.'/protocol/openid-connect/userinfo') {
            return $this->handleUserinfoRequest($request);
        }

        if ($path === $issuerPath.'/protocol/openid-connect/token') {
            return $this->handleTokenRequest($request);
        }

        return Http::response(['error' => 'not_found'], 404);
    }

    private function handleTokenRequest(HttpRequest $request): PromiseInterface
    {
        $this->tokenRequestCount++;
        $form = $request->data();
        $code = is_string($form['code'] ?? null) ? $form['code'] : '';
        $issuedCode = $this->issuedCodes[$code] ?? null;
        unset($this->issuedCodes[$code]);

        if (! $this->isClientAuthenticated($request, $form)) {
            return Http::response(['error' => 'invalid_client'], 401);
        }

        $codeVerifier = is_string($form['code_verifier'] ?? null) ? $form['code_verifier'] : '';
        $isCodeValid = $issuedCode !== null
            && ($form['grant_type'] ?? null) === 'authorization_code'
            && ($form['redirect_uri'] ?? null) === $issuedCode['redirect_uri']
            && hash_equals($issuedCode['code_challenge'], JWT::urlsafeB64Encode(hash('sha256', $codeVerifier, true)));

        if (! $isCodeValid) {
            return Http::response(['error' => 'invalid_grant'], 400);
        }

        $nonceClaim = $issuedCode['nonce'] === null ? [] : ['nonce' => $issuedCode['nonce']];
        $idTokenClaims = $this->idTokenClaims([...$nonceClaim, ...$issuedCode['claims']]);
        $accessToken = bin2hex(random_bytes(16));
        $this->issuedAccessTokens[$accessToken] = [
            ...array_intersect_key($idTokenClaims, array_flip(['sub', 'email', 'email_verified', 'name'])),
            ...$issuedCode['userinfo_claims'],
        ];
        $tokenResponse = [
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 300,
            'id_token' => $this->sign($idTokenClaims),
        ];

        if ($this->tokenResponseModifier !== null) {
            $tokenResponse = ($this->tokenResponseModifier)($tokenResponse);
        }

        return Http::response($tokenResponse);
    }

    private function handleUserinfoRequest(HttpRequest $request): PromiseInterface
    {
        $this->userinfoRequestCount++;
        $authorizationHeader = $request->header('Authorization')[0] ?? null;
        $authorization = is_string($authorizationHeader) ? $authorizationHeader : '';
        $userinfoClaims = $this->issuedAccessTokens[substr($authorization, strlen('Bearer '))] ?? null;

        if (! str_starts_with($authorization, 'Bearer ') || $userinfoClaims === null) {
            return Http::response(['error' => 'invalid_token'], 401);
        }

        return Http::response($userinfoClaims);
    }

    /**
     * @param  array<array-key, mixed>  $form
     */
    private function isClientAuthenticated(HttpRequest $request, array $form): bool
    {
        if ($this->clientSecret === null) {
            return ($form['client_id'] ?? null) === $this->clientId && ! isset($form['client_secret']);
        }

        $expectedBasicHeader = 'Basic '.base64_encode(urlencode($this->clientId).':'.urlencode($this->clientSecret));

        if ($request->hasHeader('Authorization')) {
            return $request->header('Authorization')[0] === $expectedBasicHeader;
        }

        return ($form['client_id'] ?? null) === $this->clientId && ($form['client_secret'] ?? null) === $this->clientSecret;
    }

    /**
     * @param  array<array-key, mixed>  $parameters
     */
    private function stringParameter(array $parameters, string $name): ?string
    {
        $value = $parameters[$name] ?? null;

        return is_string($value) ? $value : null;
    }

    private function expect(bool $isSatisfied, string $requirement): void
    {
        if (! $isSatisfied) {
            throw new RuntimeException("FakeIdentityProvider: the authorization request has an invalid {$requirement}.");
        }
    }
}
