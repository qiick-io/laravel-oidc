<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Outbound\Http\HttpRequestOptions;
use Qiick\Outbound\Http\OutboundHttpException;
use Qiick\Outbound\Http\OutboundRequest;
use Qiick\Outbound\Http\PinnedHttpClient;
use Qiick\Outbound\Ssrf\UnsafeUrl;
use Qiick\Outbound\Ssrf\UrlGuardOptions;

/**
 * The only way the package talks to an IdP from the server. Every call goes
 * through qiick/laravel-outbound's SSRF guard and pinned client: authorize,
 * CURLOPT_CONNECT_TO pin, no transport redirects, timeouts and response size
 * limits. Discovery, JWKS, token and userinfo all use this path.
 *
 * Errors carry the URL host, the HTTP status and the OAuth `error` code at
 * most; never a request or response body, which may hold codes or tokens.
 *
 * @internal Not part of the public API (docs/public-api.md); it can change in any release.
 */
final readonly class IdentityProviderHttpService
{
    public function __construct(
        private PinnedHttpClient $pinnedHttp,
        private UrlGuardOptions $urlGuardOptions,
        private int $timeoutSeconds,
        private int $connectTimeoutSeconds = 10,
        private int $maxResponseBytes = 1_048_576,
    ) {}

    /**
     * @param  array<string, string>  $headers
     * @return array<string, mixed>
     *
     * @throws IdentityProviderRequestException
     */
    public function getJson(string $url, #[\SensitiveParameter] array $headers = []): array
    {
        return $this->send(
            'GET',
            $url,
            static function (OutboundRequest $request) use ($headers): void {
                $request->accept('application/json')->withHeaders($headers);
            },
        );
    }

    /**
     * POSTs an `application/x-www-form-urlencoded` body (RFC 6749 4.1.3).
     *
     * @param  array<string, string>  $form
     * @param  array<string, string>  $headers
     * @return array<string, mixed>
     *
     * @throws IdentityProviderRequestException
     */
    public function postForm(string $url, #[\SensitiveParameter] array $form, #[\SensitiveParameter] array $headers = []): array
    {
        return $this->send(
            'POST',
            $url,
            static function (OutboundRequest $request) use ($form, $headers): void {
                $request->accept('application/json')->withHeaders($headers)->asForm($form);
            },
        );
    }

    /**
     * Maps outbound {@see UnsafeUrl} reasons onto the package's public wording.
     * Used by {@see DiscoveryService} for browser endpoints as well.
     */
    public static function messageForUnsafeUrl(UnsafeUrl $exception, string $host): string
    {
        $reason = $exception->reason();

        return match (true) {
            str_contains($reason, 'https') && str_contains($reason, 'allowed'),
            str_contains($reason, 'http and https') => 'OIDC endpoints must use https.',
            str_contains($reason, 'credentials') => 'OIDC endpoints must not contain credentials.',
            str_contains($reason, 'absolute') => 'OIDC endpoint is not an absolute URL.',
            str_contains($reason, 'could not be resolved') => "OIDC endpoint host [{$host}] does not resolve.",
            str_contains($reason, 'disallowed address') => "OIDC endpoint host [{$host}] resolves to a disallowed address. "
                .'Set OIDC_ALLOW_PRIVATE_HOSTS=true only for an IdP on a private network.',
            str_contains($reason, 'invalid') => "OIDC endpoint host [{$host}] is invalid.",
            default => "OIDC endpoint host [{$host}] is not allowed (private, loopback or metadata address). "
                .'Set OIDC_ALLOW_PRIVATE_HOSTS=true only for an IdP on a private network.',
        };
    }

    /**
     * `0` keeps the historical "no limit" meaning by mapping onto a 24-hour
     * ceiling, so outbound's ≥1s / ≤limits contract still holds.
     */
    public static function resolveTimeoutSeconds(int $configuredSeconds): int
    {
        if ($configuredSeconds === 0) {
            return 86_400;
        }

        return max(1, $configuredSeconds);
    }

    /**
     * @param  callable(OutboundRequest): void  $configure
     * @return array<string, mixed>
     *
     * @throws IdentityProviderRequestException
     */
    private function send(string $method, string $url, callable $configure): array
    {
        $host = (string) parse_url($url, PHP_URL_HOST);
        $timeoutSeconds = self::resolveTimeoutSeconds($this->timeoutSeconds);
        $connectTimeoutSeconds = min(
            self::resolveTimeoutSeconds($this->connectTimeoutSeconds),
            $timeoutSeconds,
        );

        try {
            $response = $this->pinnedHttp->send(
                $method,
                $url,
                $configure,
                new HttpRequestOptions(
                    timeoutSeconds: $timeoutSeconds,
                    connectTimeoutSeconds: $connectTimeoutSeconds,
                    followRedirects: false,
                    maxRedirects: 0,
                    maxResponseBytes: $this->maxResponseBytes,
                    urlOptions: $this->urlGuardOptions,
                ),
            );
        } catch (UnsafeUrl $exception) {
            throw new IdentityProviderRequestException(
                self::messageForUnsafeUrl($exception, $host),
                previous: $exception,
            );
        } catch (OutboundHttpException $exception) {
            throw new IdentityProviderRequestException(
                "OIDC request to [{$host}] failed: connection error.",
                previous: $exception,
            );
        }

        $payload = $response->json();

        if (! $response->successful()) {
            $errorCode = is_array($payload) && is_string($payload['error'] ?? null) && preg_match('/^[\w.-]{1,64}$/', $payload['error']) === 1
                ? " ({$payload['error']})"
                : '';

            throw new IdentityProviderRequestException("OIDC request to [{$host}] failed with HTTP {$response->status()}{$errorCode}.");
        }

        if (! is_array($payload) || array_is_list($payload)) {
            throw new IdentityProviderRequestException("OIDC response from [{$host}] is not a JSON object.");
        }

        /** @var array<string, mixed> $payload */
        return $payload;
    }
}
