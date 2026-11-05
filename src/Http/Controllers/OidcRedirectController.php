<?php

declare(strict_types=1);

namespace Qiick\Oidc\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Exceptions\OidcException;
use Qiick\Oidc\Services\AuthorizationCodeFlowService;

/**
 * `GET {prefix}/redirect`: the SSO button. Sends the browser to the IdP.
 */
final class OidcRedirectController
{
    public function __invoke(
        Request $request,
        ProviderConfigurationRepositoryContract $configurationRepository,
        AuthorizationCodeFlowService $authorizationCodeFlow,
    ): RedirectResponse {
        abort_unless($configurationRepository->isEnabled(), 404);

        try {
            $requestedAuthenticationContext = Config::get('oidc.mfa.request_acr_values');

            return $authorizationCodeFlow->redirect(
                $request,
                is_string($requestedAuthenticationContext) && $requestedAuthenticationContext !== '' ? ['acr_values' => $requestedAuthenticationContext] : [],
            );
        } catch (OidcException $exception) {
            return OidcCallbackController::backToLogin($exception);
        }
    }
}
