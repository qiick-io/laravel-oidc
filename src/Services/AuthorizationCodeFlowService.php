<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Firebase\JWT\JWT;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Date;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Data\ProviderConfigurationData;
use Qiick\Oidc\Enums\TokenEndpointAuthMethodEnum;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Exceptions\InvalidCallbackException;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Exceptions\OidcNotConfiguredException;

/**
 * The OIDC authorization code flow with PKCE (RFC 7636, `S256` only), `state`
 * and `nonce` on every login, as the accepted SSO design requires.
 *
 * redirect() stores a pending login in the session, keyed by its `state`, and
 * sends the browser to the IdP. handleCallback() consumes that pending login
 * exactly once, exchanges the code with the PKCE verifier and returns the
 * identity from the validated id_token, enriched with the userinfo claims.
 *
 * Several pending logins can coexist (two tabs), up to MAXIMUM_PENDING_LOGINS;
 * each expires after PENDING_LOGIN_SECONDS.
 *
 * The package does not log the user in: the app maps the identity to a local
 * user, regenerates the session and calls Auth::login().
 */
final readonly class AuthorizationCodeFlowService
{
    public const string SESSION_KEY = 'oidc.pending_logins';

    public const int PENDING_LOGIN_SECONDS = 600;

    public const int MAXIMUM_PENDING_LOGINS = 5;

    /**
     * Authorization request parameters the package always sets itself.
     */
    private const array RESERVED_PARAMETERS = [
        'response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method',
    ];

    /**
     * Claims that only count when they come from the signed id_token. The
     * userinfo response is not signed, so these are dropped from it (an `amr`
     * there could otherwise fake MFA).
     */
    private const array ID_TOKEN_ONLY_CLAIMS = ['iss', 'aud', 'azp', 'exp', 'iat', 'nbf', 'nonce', 'sid', 'auth_time', 'amr', 'acr'];

    public function __construct(
        private ProviderConfigurationRepositoryContract $configurationRepository,
        private DiscoveryService $discovery,
        private IdentityProviderHttpService $identityProviderHttp,
        private IdTokenValidatorService $idTokenValidator,
        private UserinfoService $userinfo,
        private bool $shouldFetchUserinfo,
    ) {}

    /**
     * Starts a login: stores `state`, `nonce` and the PKCE verifier in the
     * session and redirects the browser to the authorization endpoint.
     *
     * @param  array<string, string>  $additionalParameters  optional request parameters such as `prompt`,
     *                                                       `login_hint` or `acr_values`; reserved ones are ignored
     *
     * @throws OidcNotConfiguredException
     * @throws IdentityProviderRequestException when discovery fails
     */
    public function redirect(Request $request, array $additionalParameters = []): RedirectResponse
    {
        $configuration = $this->configurationRepository->configuration();
        $discovery = $this->discovery->discover($configuration);

        $state = $this->randomToken(32);
        $nonce = $this->randomToken(32);
        $codeVerifier = $this->randomToken(64);

        $this->storePendingLogin($request->session(), $state, [
            'issuer' => $configuration->issuer,
            'redirect_uri' => $configuration->redirectUri,
            'nonce' => $nonce,
            'code_verifier' => $codeVerifier,
            'expires_at' => Date::now()->getTimestamp() + self::PENDING_LOGIN_SECONDS,
        ]);

        $parameters = [
            ...array_diff_key($additionalParameters, array_flip(self::RESERVED_PARAMETERS)),
            'response_type' => 'code',
            'client_id' => $configuration->clientId,
            'redirect_uri' => $configuration->redirectUri,
            'scope' => implode(' ', $configuration->scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => JWT::urlsafeB64Encode(hash('sha256', $codeVerifier, true)),
            'code_challenge_method' => 'S256',
        ];

        $separator = str_contains($discovery->authorizationEndpoint, '?') ? '&' : '?';

        return new RedirectResponse(
            $discovery->authorizationEndpoint.$separator.http_build_query($parameters, '', '&', PHP_QUERY_RFC3986)
        );
    }

    /**
     * Completes a login on the redirect URI.
     *
     * @throws InvalidCallbackException when the authorization response cannot be accepted
     * @throws IdentityProviderRequestException when the token request fails
     * @throws InvalidTokenException when the id_token fails validation
     * @throws OidcNotConfiguredException
     */
    public function handleCallback(Request $request): AuthenticatedIdentityData
    {
        $configuration = $this->configurationRepository->configuration();
        $pendingLogin = $this->pullPendingLogin($request->session(), $request->query('state'));

        if ($pendingLogin['issuer'] !== $configuration->issuer || $pendingLogin['redirect_uri'] !== $configuration->redirectUri) {
            throw new InvalidCallbackException('The OIDC settings changed during the login. Start again.');
        }

        $errorCode = $request->query('error');

        if ($errorCode !== null) {
            $safeErrorCode = is_string($errorCode) && preg_match('/^[\w.-]{1,64}$/', $errorCode) === 1 ? $errorCode : 'unknown';

            throw new InvalidCallbackException("The IdP refused the login ({$safeErrorCode}).");
        }

        $discovery = $this->discovery->discover($configuration);
        $this->assertResponseIssuer($request->query('iss'), $configuration->issuer, $discovery->isAuthorizationResponseIssuerSupported);

        $code = $request->query('code');

        if (! is_string($code) || $code === '') {
            throw new InvalidCallbackException('The authorization response has no code.');
        }

        $tokenResponse = $this->identityProviderHttp->postForm(
            $discovery->tokenEndpoint,
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $pendingLogin['redirect_uri'],
                'code_verifier' => $pendingLogin['code_verifier'],
                ...$this->clientAuthenticationForm($configuration),
            ],
            $this->clientAuthenticationHeaders($configuration),
        );

        $idToken = $tokenResponse['id_token'] ?? null;
        $accessToken = $tokenResponse['access_token'] ?? null;

        if (! is_string($idToken) || ! is_string($accessToken)) {
            throw new IdentityProviderRequestException('The token response has no id_token or access_token.');
        }

        $claims = $this->idTokenValidator->validate($idToken, $discovery, $configuration, $pendingLogin['nonce'], $accessToken);
        $subject = $claims['sub'];
        $sessionId = $claims['sid'] ?? null;

        if ($this->shouldFetchUserinfo) {
            $userinfoClaims = array_diff_key($this->userinfo->fetch($discovery, $accessToken, $subject), array_flip(self::ID_TOKEN_ONLY_CLAIMS));
            $claims = [...$userinfoClaims, ...$claims];
        }

        return new AuthenticatedIdentityData(
            issuer: $discovery->issuer,
            subject: $subject,
            claims: $claims,
            idToken: $idToken,
            accessToken: $accessToken,
            sessionId: is_string($sessionId) && $sessionId !== '' ? $sessionId : null,
        );
    }

    /**
     * @param  array{issuer: string, redirect_uri: string, nonce: string, code_verifier: string, expires_at: int}  $pendingLogin
     */
    private function storePendingLogin(Session $session, string $state, array $pendingLogin): void
    {
        $now = Date::now()->getTimestamp();
        $pendingLogins = array_filter(
            $this->pendingLogins($session),
            fn (array $storedLogin): bool => $storedLogin['expires_at'] > $now,
        );
        $pendingLogins[$state] = $pendingLogin;

        $session->put(self::SESSION_KEY, array_slice($pendingLogins, -self::MAXIMUM_PENDING_LOGINS, null, true));
    }

    /**
     * Removes the pending login before any other check, so a `state` can never
     * be used twice, not even after a failed callback.
     *
     * @return array{issuer: string, redirect_uri: string, nonce: string, code_verifier: string, expires_at: int}
     *
     * @throws InvalidCallbackException
     */
    private function pullPendingLogin(Session $session, mixed $state): array
    {
        $pendingLogins = $this->pendingLogins($session);

        if (! is_string($state) || $state === '' || ! array_key_exists($state, $pendingLogins)) {
            throw new InvalidCallbackException('The authorization response has a missing or unknown state.');
        }

        $pendingLogin = $pendingLogins[$state];
        unset($pendingLogins[$state]);
        $session->put(self::SESSION_KEY, $pendingLogins);

        if ($pendingLogin['expires_at'] <= Date::now()->getTimestamp()) {
            throw new InvalidCallbackException('The login took too long. Start again.');
        }

        return $pendingLogin;
    }

    /**
     * @return array<string, array{issuer: string, redirect_uri: string, nonce: string, code_verifier: string, expires_at: int}>
     */
    private function pendingLogins(Session $session): array
    {
        $pendingLogins = $session->get(self::SESSION_KEY, []);

        /** @var array<string, array{issuer: string, redirect_uri: string, nonce: string, code_verifier: string, expires_at: int}> */
        return is_array($pendingLogins) ? $pendingLogins : [];
    }

    /**
     * RFC 9207: when the IdP sends `iss` in the authorization response it must
     * be our issuer, and an IdP that advertises the parameter must send it.
     * This stops mix-up attacks between several IdPs.
     *
     * @throws InvalidCallbackException
     */
    private function assertResponseIssuer(mixed $responseIssuer, string $issuer, bool $isIssuerParameterRequired): void
    {
        if ($responseIssuer === null && ! $isIssuerParameterRequired) {
            return;
        }

        if ($responseIssuer !== $issuer) {
            throw new InvalidCallbackException('The authorization response [iss] does not match the issuer.');
        }
    }

    /**
     * @return array<string, string>
     */
    private function clientAuthenticationForm(ProviderConfigurationData $configuration): array
    {
        if ($configuration->isPublicClient()) {
            return ['client_id' => $configuration->clientId];
        }

        if ($configuration->tokenEndpointAuthMethod === TokenEndpointAuthMethodEnum::ClientSecretPost) {
            return ['client_id' => $configuration->clientId, 'client_secret' => (string) $configuration->clientSecret];
        }

        return [];
    }

    /**
     * `client_secret_basic` form-encodes id and secret before Base64 (RFC 6749
     * 2.3.1), which plain HTTP basic auth does not do.
     *
     * @return array<string, string>
     */
    private function clientAuthenticationHeaders(ProviderConfigurationData $configuration): array
    {
        if ($configuration->isPublicClient() || $configuration->tokenEndpointAuthMethod !== TokenEndpointAuthMethodEnum::ClientSecretBasic) {
            return [];
        }

        $credentials = urlencode($configuration->clientId).':'.urlencode((string) $configuration->clientSecret);

        return ['Authorization' => 'Basic '.base64_encode($credentials)];
    }

    /**
     * Base64url without padding. 32 bytes give `state` and `nonce` 256 bits;
     * 64 bytes give an 86-character PKCE verifier (RFC 7636 4.1: 43 to 128).
     *
     * @param  int<1, max>  $byteCount
     */
    private function randomToken(int $byteCount): string
    {
        return JWT::urlsafeB64Encode(random_bytes($byteCount));
    }
}
