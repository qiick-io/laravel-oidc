<?php

declare(strict_types=1);

namespace Qiick\Oidc\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Services\RpInitiatedLogoutService;

/**
 * `GET {prefix}/logged-out`: where the IdP sends the browser after
 * RP-initiated logout (standards review S7). It checks the logout `state`
 * and redirects to `oidc.logout.redirect_to`, which comes from config only,
 * so the route cannot be used as an open redirect.
 *
 * A missing or wrong state still redirects, with a warning: the local logout
 * already happened, so a refusal would protect nothing and only leave the
 * user on an error page.
 */
final class PostLogoutReturnController
{
    public function __invoke(
        Request $request,
        ProviderConfigurationRepositoryContract $configurationRepository,
        RpInitiatedLogoutService $rpInitiatedLogout,
    ): RedirectResponse {
        abort_unless($configurationRepository->isEnabled(), 404);

        if (! $rpInitiatedLogout->hasMatchingReturnState($request)) {
            Log::warning('OIDC post-logout return without a matching state; redirecting anyway.');
        }

        $redirectTo = Config::get('oidc.logout.redirect_to');

        return new RedirectResponse(url(is_string($redirectTo) ? $redirectTo : '/'));
    }
}
