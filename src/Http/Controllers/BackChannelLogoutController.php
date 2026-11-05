<?php

declare(strict_types=1);

namespace Qiick\Oidc\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Exceptions\OidcException;
use Qiick\Oidc\Services\BackChannelLogoutService;

/**
 * `POST {prefix}/backchannel-logout`, called by the IdP server, never by a
 * browser. Responses follow Back-Channel Logout 1.0, 2.8: 200 on success,
 * 400 with an OAuth error otherwise, never cached.
 */
final class BackChannelLogoutController
{
    public function __invoke(
        Request $request,
        ProviderConfigurationRepositoryContract $configurationRepository,
        BackChannelLogoutService $backChannelLogout,
    ): Response|JsonResponse {
        abort_unless($configurationRepository->isEnabled(), 404);

        $logoutToken = $request->input('logout_token');

        try {
            if (! is_string($logoutToken) || $logoutToken === '') {
                return $this->error('Missing logout_token.');
            }

            $backChannelLogout->handle($logoutToken);
        } catch (OidcException $exception) {
            logger()->warning('OIDC back-channel logout refused: '.$exception->getMessage());

            return $this->error($exception->getMessage());
        }

        return new Response('', 200, ['Cache-Control' => 'no-store']);
    }

    private function error(string $description): JsonResponse
    {
        return new JsonResponse(
            ['error' => 'invalid_request', 'error_description' => $description],
            400,
            ['Cache-Control' => 'no-store'],
        );
    }
}
