<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Firebase\JWT\JWT;
use Illuminate\Contracts\Cookie\QueueingFactory;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;

/**
 * RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0): after the app
 * ends its own session, the browser is sent to the IdP's
 * `end_session_endpoint`, so the IdP session ends too and the next SSO login
 * asks for credentials again.
 *
 * Read the URL before invalidating the session, because it needs the stored
 * id_token:
 *
 *     $endSessionUrl = $logout->endSessionUrl($request->session());
 *     Auth::logout(); $request->session()->invalidate();
 *     return $endSessionUrl !== null ? redirect()->away($endSessionUrl) : redirect('/');
 *
 * When the IdP returns to the package route `oidc.logged-out` (the default
 * post-logout URI), the request carries a random `state` (RP-Initiated Logout
 * 1.0 §2) that the route checks before redirecting (standards review S7). The
 * app invalidates its session right after this call, so the state lives in a
 * short-lived cookie scoped to the package routes instead.
 */
final readonly class RpInitiatedLogoutService
{
    public const string STATE_COOKIE = 'oidc_logout_state';

    public function __construct(
        private ProviderConfigurationRepositoryContract $configurationRepository,
        private DiscoveryService $discovery,
        private IdentitySessionService $identitySession,
        private QueueingFactory $cookies,
    ) {}

    /**
     * The IdP logout URL for the current session, or null when the session
     * did not come from an SSO login, SSO is off, the issuer changed since
     * the login, or the IdP has no end_session_endpoint.
     *
     * @throws IdentityProviderRequestException when discovery fails
     */
    public function endSessionUrl(Session $session): ?string
    {
        $identity = $this->identitySession->current($session);

        if ($identity === null || ! $this->configurationRepository->isEnabled()) {
            return null;
        }

        $configuration = $this->configurationRepository->configuration();

        if ($identity->issuer !== $configuration->issuer) {
            return null;
        }

        $endSessionEndpoint = $this->discovery->discover($configuration)->endSessionEndpoint;

        if ($endSessionEndpoint === null) {
            return null;
        }

        // http_build_query() leaves out null values, such as a state the app's own URI does not get.
        $parameters = [
            'id_token_hint' => $identity->idToken,
            'client_id' => $configuration->clientId,
            'post_logout_redirect_uri' => $configuration->postLogoutRedirectUri,
            'state' => $this->stateFor($configuration->postLogoutRedirectUri),
        ];

        $separator = str_contains($endSessionEndpoint, '?') ? '&' : '?';

        return $endSessionEndpoint.$separator.http_build_query($parameters, arg_separator: '&', encoding_type: PHP_QUERY_RFC3986);
    }

    /**
     * Whether the post-logout return carries the state this browser was given,
     * within its ten minutes. Always forgets the cookie: a state is used once.
     */
    public function hasMatchingReturnState(Request $request): bool
    {
        $storedState = $request->cookie(self::STATE_COOKIE);
        $returnedState = $request->query('state');
        $this->cookies->queue($this->cookies->forget(self::STATE_COOKIE, $this->cookiePath()));

        if (! is_string($storedState) || ! is_string($returnedState) || substr_count($storedState, '.') !== 1) {
            return false;
        }

        [$expiresAt, $state] = explode('.', $storedState);

        return (int) $expiresAt >= Date::now()->getTimestamp() && hash_equals($state, $returnedState);
    }

    /**
     * A fresh 256-bit state when the IdP returns to the package route, kept
     * for ten minutes in an HttpOnly, SameSite=Lax cookie on the package path
     * (Secure when the return URI is https); Lax cookies are sent on the
     * IdP's top-level redirect back. Null for an app's own post-logout URI,
     * which the package cannot check.
     */
    private function stateFor(?string $postLogoutRedirectUri): ?string
    {
        if ($postLogoutRedirectUri === null || ! Route::has('oidc.logged-out') || $postLogoutRedirectUri !== route('oidc.logged-out')) {
            return null;
        }

        $state = JWT::urlsafeB64Encode(random_bytes(32));
        $expiresAt = Date::now()->addMinutes(10)->getTimestamp();

        $this->cookies->queue($this->cookies->make(
            name: self::STATE_COOKIE,
            value: "{$expiresAt}.{$state}",
            minutes: 10,
            path: $this->cookiePath(),
            secure: str_starts_with($postLogoutRedirectUri, 'https://'),
            httpOnly: true,
            sameSite: 'lax',
        ));

        return $state;
    }

    private function cookiePath(): string
    {
        return '/'.trim(Config::string('oidc.routes.prefix', 'auth/oidc'), '/');
    }
}
