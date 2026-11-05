<?php

declare(strict_types=1);

namespace Qiick\Oidc\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Exceptions\LoginRefusedException;
use Qiick\Oidc\Exceptions\OidcException;
use Qiick\Oidc\Services\AuthorizationCodeFlowService;
use Qiick\Oidc\Services\OidcLoginService;

/**
 * `GET {prefix}/callback`: the redirect URI registered at the IdP.
 *
 * A failure always goes back to the login page with a message under the
 * `email` key, like Externa's SSO login today. Never back(): the referer is
 * the IdP, and back() would bounce between IdP and callback forever.
 */
final class OidcCallbackController
{
    public function __invoke(
        Request $request,
        ProviderConfigurationRepositoryContract $configurationRepository,
        AuthorizationCodeFlowService $authorizationCodeFlow,
        OidcLoginService $oidcLogin,
    ): RedirectResponse {
        abort_unless($configurationRepository->isEnabled(), 404);

        try {
            $oidcLogin->login($request, $authorizationCodeFlow->handleCallback($request));
        } catch (OidcException $exception) {
            return self::backToLogin($exception);
        }

        return redirect()->intended(Config::string('oidc.home', '/'));
    }

    /**
     * Refusals carry a message for the user; protocol and IdP failures get a
     * generic one, and their technical message goes to the log only.
     */
    public static function backToLogin(OidcException $exception): RedirectResponse
    {
        if ($exception instanceof LoginRefusedException) {
            $message = __($exception->getMessage());
        } else {
            logger()->warning('OIDC login failed: '.$exception->getMessage(), ['exception' => $exception::class]);
            $message = __('SSO login failed. Try again or use email and password.');
        }

        return redirect(Config::string('oidc.login_url', '/login'))->withErrors(['email' => $message]);
    }
}
