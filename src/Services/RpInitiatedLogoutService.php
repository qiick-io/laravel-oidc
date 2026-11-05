<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Session\Session;
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
 */
final readonly class RpInitiatedLogoutService
{
    public function __construct(
        private ProviderConfigurationRepositoryContract $configurationRepository,
        private DiscoveryService $discovery,
        private IdentitySessionService $identitySession,
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

        $parameters = array_filter([
            'id_token_hint' => $identity->idToken,
            'client_id' => $configuration->clientId,
            'post_logout_redirect_uri' => $configuration->postLogoutRedirectUri,
        ], fn (?string $value): bool => $value !== null);

        $separator = str_contains($endSessionEndpoint, '?') ? '&' : '?';

        return $endSessionEndpoint.$separator.http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }
}
