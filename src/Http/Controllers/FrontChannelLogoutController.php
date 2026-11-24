<?php

declare(strict_types=1);

namespace Qiick\Oidc\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Config;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Data\LogoutTokenData;
use Qiick\Oidc\Services\SessionRevocationService;

/**
 * `GET {prefix}/frontchannel-logout` for an IdP iframe (OIDC Front-Channel
 * Logout 1.0). Off unless `oidc.frontchannel_logout.enabled` is on (S3).
 *
 * No `web` middleware: the cross-site iframe does not send the session cookie
 * under SameSite=lax, and the endpoint only needs `iss` and `sid` from the
 * query string.
 */
final class FrontChannelLogoutController
{
    public function __invoke(
        Request $request,
        ProviderConfigurationRepositoryContract $configurationRepository,
        SessionRevocationService $sessionRevocation,
    ): Response {
        abort_unless(
            $configurationRepository->isEnabled() && Config::boolean('oidc.frontchannel_logout.enabled'),
            404,
        );

        $issuer = $request->query('iss');
        $sessionId = $request->query('sid');

        if (! is_string($issuer) || $issuer === '' || ! is_string($sessionId) || $sessionId === '') {
            return $this->error(400, 'Front-channel logout requires both [iss] and [sid].');
        }

        // The revocation table keeps `sid` in a 255-character column.
        if (strlen($sessionId) > 255) {
            return $this->error(400, 'Front-channel logout [sid] is longer than 255 characters.');
        }

        if (trim($sessionId) !== $sessionId) {
            return $this->error(400, 'Front-channel logout [sid] has leading or trailing whitespace.');
        }

        // isEnabled() above guarantees the configuration can be built.
        if ($issuer !== $configurationRepository->configuration()->issuer) {
            return $this->error(400, 'Front-channel logout [iss] does not match the configured issuer.');
        }

        // Without a jti there is no replay key to collide with: every call stores a row.
        $sessionRevocation->revoke(new LogoutTokenData(
            issuer: $issuer,
            subject: null,
            sessionId: $sessionId,
            tokenId: null,
            expiresAt: null,
            channel: 'frontchannel',
        ));

        $issuerOrigin = $this->issuerOrigin($issuer);

        return new Response('', 200, [
            'Cache-Control' => 'no-store',
            'Content-Security-Policy' => 'frame-ancestors '.$issuerOrigin,
        ]);
    }

    private function error(int $status, string $description): Response
    {
        return new Response($description, $status, ['Cache-Control' => 'no-store']);
    }

    /**
     * Scheme + host (+ port) of the configured issuer for frame-ancestors.
     */
    private function issuerOrigin(string $issuer): string
    {
        $scheme = parse_url($issuer, PHP_URL_SCHEME);
        $host = parse_url($issuer, PHP_URL_HOST);
        $port = parse_url($issuer, PHP_URL_PORT);

        // parse_url() leaves out an empty scheme or host rather than returning ''.
        if (! is_string($scheme) || ! is_string($host)) {
            return "'none'";
        }

        return $scheme.'://'.$host.($port !== null ? ':'.$port : '');
    }
}
