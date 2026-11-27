<?php

declare(strict_types=1);

namespace Qiick\Oidc\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\RateLimiter;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Exceptions\OidcException;
use Qiick\Oidc\Services\BackChannelLogoutService;

/**
 * `POST {prefix}/backchannel-logout`, called by the IdP server, never by a
 * browser. Responses follow Back-Channel Logout 1.0, 2.8: 200 on success,
 * 400 with an OAuth error on rejection, or 429 above the rejection budget.
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
                return $this->error($request, 'Missing logout_token.');
            }

            $backChannelLogout->handle($logoutToken);
        } catch (OidcException $exception) {
            return $this->error($request, $exception->getMessage(), shouldLog: true);
        }

        return new Response('', 200, ['Cache-Control' => 'no-store']);
    }

    /** Count rejections only, so an IdP can still deliver every valid logout in a burst. */
    private function error(Request $request, string $description, bool $shouldLog = false): JsonResponse
    {
        $limit = Config::get('oidc.backchannel_logout.rate_limit');
        $limiterKey = sprintf('oidc:backchannel-logout:%s', hash('sha256', (string) $request->ip()));

        if (is_int($limit) && RateLimiter::increment($limiterKey) > $limit) {
            return new JsonResponse(
                ['error' => 'too_many_requests'],
                429,
                ['Cache-Control' => 'no-store', 'Retry-After' => sprintf('%d', RateLimiter::availableIn($limiterKey))],
            );
        }

        if ($shouldLog) {
            logger()->warning('OIDC back-channel logout refused: '.$description);
        }

        return new JsonResponse(
            ['error' => 'invalid_request', 'error_description' => $description],
            400,
            ['Cache-Control' => 'no-store'],
        );
    }
}
