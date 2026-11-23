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
 *
 * A pending login also remembers the `max_age` and the `acr` values it asked
 * for, so the callback checks the answer against this login's own request
 * (standards review S2). Pending logins stored before S2 lack both keys and
 * read as "nothing asked".
 *
 * @phpstan-type PendingLogin array{issuer: string, redirect_uri: string, nonce: string, code_verifier: string, expires_at: int, max_age?: int|null, requested_acr_values?: list<string>|null}
 */
final readonly class AuthorizationCodeFlowService
{
    public const string SESSION_KEY = 'oidc.pending_logins';

    public const int PENDING_LOGIN_SECONDS = 600;

    public const int MAXIMUM_PENDING_LOGINS = 5;

    public function __construct(
        private ProviderConfigurationRepositoryContract $configurationRepository,
        private DiscoveryService $discovery,
        private IdentityProviderHttpService $identityProviderHttp,
        private IdTokenValidatorService $idTokenValidator,
        private UserinfoService $userinfo,
        private bool $shouldFetchUserinfo,
        private int $leewaySeconds,
        private bool $isRequestedAcrRequired,
    ) {}

    /**
     * Starts a login: stores `state`, `nonce` and the PKCE verifier in the
     * session and redirects the browser to the authorization endpoint.
     *
     * @param  array<string, string>  $additionalParameters  optional request parameters such as `prompt`,
     *                                                       `login_hint`, `max_age`, `acr_values` or `claims`.
     *                                                       The parameters the package sets itself always win;
     *                                                       a `max_age` here wins over the configured one.
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
        $requestedMaxAge = filter_var($additionalParameters['max_age'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0], 'flags' => FILTER_NULL_ON_FAILURE]);
        $maxAge = $requestedMaxAge ?? $configuration->maxAge;

        $this->storePendingLogin($request->session(), $state, [
            'issuer' => $configuration->issuer,
            'redirect_uri' => $configuration->redirectUri,
            'nonce' => $nonce,
            'code_verifier' => $codeVerifier,
            'expires_at' => Date::now()->getTimestamp() + self::PENDING_LOGIN_SECONDS,
            'max_age' => $maxAge,
            'requested_acr_values' => $this->requestedAcrValues($additionalParameters),
        ]);

        // Later keys win: the package's own parameters override any
        // additional parameter of the same name.
        $parameters = [
            ...$additionalParameters,
            ...($maxAge === null ? [] : ['max_age' => $maxAge]),
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
            $discovery->authorizationEndpoint.$separator.http_build_query($parameters, arg_separator: '&', encoding_type: PHP_QUERY_RFC3986)
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
        $this->assertAuthenticationIsRecent($claims, $pendingLogin['max_age'] ?? null);
        $isRequestedAuthenticationContextMet = $this->isRequestedAuthenticationContextMet($claims, $pendingLogin['requested_acr_values'] ?? null);
        $subject = $claims['sub'];
        $sessionId = $claims['sid'] ?? null;

        if ($this->shouldFetchUserinfo) {
            $userinfoClaims = array_diff_key($this->userinfo->fetch($discovery, $accessToken, $subject), array_flip($this->idTokenOnlyClaims()));
            $claims = [...$userinfoClaims, ...$claims];
        }

        return new AuthenticatedIdentityData(
            issuer: $discovery->issuer,
            subject: $subject,
            claims: $claims,
            idToken: $idToken,
            accessToken: $accessToken,
            sessionId: is_string($sessionId) && $sessionId !== '' ? $sessionId : null,
            isRequestedAuthenticationContextMet: $isRequestedAuthenticationContextMet,
        );
    }

    /**
     * Claims that only count when they come from the signed id_token. The
     * userinfo response is not signed, so these are dropped from it (an `amr`
     * there could otherwise fake MFA). `iss`, `aud`, `exp`, `iat` and `nonce`
     * are not listed: the validated id_token always has them, and its claims
     * win every conflict.
     *
     * @return list<string>
     */
    private function idTokenOnlyClaims(): array
    {
        return ['azp', 'nbf', 'sid', 'auth_time', 'amr', 'acr'];
    }

    /**
     * The `acr` values this login asks for: `acr_values` (OIDC Core 3.1.2.1,
     * space-separated) or the `acr` member of the id_token part of the
     * `claims` parameter (5.5.1.1: `value` or `values`; `essential` alone
     * asks for any `acr`, which an empty list stands for). Null when the
     * login asks for none.
     *
     * @param  array<string, string>  $additionalParameters
     * @return list<string>|null
     */
    private function requestedAcrValues(array $additionalParameters): ?array
    {
        $requestedAcrValues = preg_split('/ +/', $additionalParameters['acr_values'] ?? '', flags: PREG_SPLIT_NO_EMPTY) ?: [];
        $claimsRequest = isset($additionalParameters['claims']) ? json_decode($additionalParameters['claims'], true) : null;
        $idTokenClaimsRequest = is_array($claimsRequest) ? ($claimsRequest['id_token'] ?? null) : null;
        $acrRequest = is_array($idTokenClaimsRequest) ? ($idTokenClaimsRequest['acr'] ?? null) : null;

        if (is_array($acrRequest)) {
            $requestedValues = is_string($acrRequest['value'] ?? null) ? [$acrRequest['value']] : ($acrRequest['values'] ?? []);

            return [...$requestedAcrValues, ...array_values(array_filter(is_array($requestedValues) ? $requestedValues : [], is_string(...)))];
        }

        return $requestedAcrValues === [] ? null : $requestedAcrValues;
    }

    /**
     * OIDC Core 3.1.3.7 step 13: when `max_age` was sent, `auth_time` is
     * required (3.1.2.1) and must not be older than max_age, with the
     * configured clock leeway.
     *
     * @param  array<string, mixed>  $claims
     *
     * @throws InvalidTokenException
     */
    private function assertAuthenticationIsRecent(array $claims, ?int $maxAge): void
    {
        if ($maxAge === null) {
            return;
        }

        $authenticationTime = $claims['auth_time'] ?? null;

        if (! is_int($authenticationTime)) {
            throw new InvalidTokenException('id_token has no numeric [auth_time], which max_age requires.');
        }

        if (Date::now()->getTimestamp() - $authenticationTime > $maxAge + $this->leewaySeconds) {
            throw new InvalidTokenException('id_token [auth_time] is older than max_age allows.');
        }
    }

    /**
     * Whether the id_token answers the `acr` this login asked for. `acr` is
     * optional and `acr_values` voluntary (OIDC Core 2, 3.1.2.1), so a miss
     * only means "MFA not proven", unless oidc.mfa.require_requested_acr
     * makes it a refusal.
     *
     * @param  array<string, mixed>  $claims
     * @param  list<string>|null  $requestedAcrValues  empty: any `acr` will do
     *
     * @throws InvalidTokenException when the requested acr is required and missing
     */
    private function isRequestedAuthenticationContextMet(array $claims, ?array $requestedAcrValues): bool
    {
        if ($requestedAcrValues === null) {
            return true;
        }

        $authenticationContext = $claims['acr'] ?? null;
        $isMet = is_string($authenticationContext)
            && ($requestedAcrValues === [] || in_array($authenticationContext, $requestedAcrValues, true));

        if (! $isMet && $this->isRequestedAcrRequired) {
            throw new InvalidTokenException('id_token [acr] is not one of the requested values.');
        }

        return $isMet;
    }

    /**
     * @param  PendingLogin  $pendingLogin
     */
    private function storePendingLogin(Session $session, string $state, array $pendingLogin): void
    {
        // The newest MAXIMUM_PENDING_LOGINS are kept, oldest first, so an
        // expired login always leaves before a live one; pullPendingLogin()
        // refuses an expired one anyway. `state` keys are random base64url
        // strings, which array_slice() never renumbers.
        $pendingLogins = $this->pendingLogins($session);
        $pendingLogins[$state] = $pendingLogin;

        $session->put(self::SESSION_KEY, array_slice($pendingLogins, -self::MAXIMUM_PENDING_LOGINS));
    }

    /**
     * Removes the pending login before any other check, so a `state` can never
     * be used twice, not even after a failed callback.
     *
     * @return PendingLogin
     *
     * @throws InvalidCallbackException
     */
    private function pullPendingLogin(Session $session, mixed $state): array
    {
        $pendingLogins = $this->pendingLogins($session);

        if (! is_string($state) || ! array_key_exists($state, $pendingLogins)) {
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
     * @return array<string, PendingLogin>
     */
    private function pendingLogins(Session $session): array
    {
        $pendingLogins = $session->get(self::SESSION_KEY, []);

        /** @var array<string, PendingLogin> */
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
