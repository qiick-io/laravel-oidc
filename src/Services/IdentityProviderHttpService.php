<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;

/**
 * The only way the package talks to an IdP from the server. Every call goes
 * through the SSRF guard, pins the checked address with CURLOPT_CONNECT_TO,
 * refuses redirects and expects a JSON object back.
 *
 * Errors carry the URL host, the HTTP status and the OAuth `error` code at
 * most; never a request or response body, which may hold codes or tokens.
 */
final readonly class IdentityProviderHttpService
{
    public function __construct(
        private HttpFactory $http,
        private RemoteUrlGuardService $remoteUrlGuard,
        private int $timeoutSeconds,
    ) {}

    /**
     * @param  array<string, string>  $headers
     * @return array<string, mixed>
     *
     * @throws IdentityProviderRequestException
     */
    public function getJson(string $url, #[\SensitiveParameter] array $headers = []): array
    {
        return $this->send($url, fn (PendingRequest $request): Response => $request->withHeaders($headers)->get($url));
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
            $url,
            fn (PendingRequest $request): Response => $request->asForm()->withHeaders($headers)->post($url, $form),
        );
    }

    /**
     * @param  callable(PendingRequest): Response  $sendRequest
     * @return array<string, mixed>
     *
     * @throws IdentityProviderRequestException
     */
    private function send(string $url, callable $sendRequest): array
    {
        $pinnedAddresses = $this->remoteUrlGuard->assertServerUrlIsSafe($url);
        $host = (string) parse_url($url, PHP_URL_HOST);

        $request = $this->http
            ->acceptJson()
            ->timeout($this->timeoutSeconds)
            ->withOptions(['allow_redirects' => false, ...$this->pinningOptions($url, $pinnedAddresses)]);

        try {
            $response = $sendRequest($request);
        } catch (ConnectionException) {
            throw new IdentityProviderRequestException("OIDC request to [{$host}] failed: connection error.");
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

    /**
     * Pins the request to the address the guard checked (CURLOPT_CONNECT_TO).
     *
     * `::ADDRESS:PORT` leaves the source host and port empty, so it matches
     * whatever host curl takes from the URL, however that host is spelt; the
     * URL host is still what TLS verifies and what the Host header says. The
     * address is always an IP literal, so curl connects without a lookup of
     * its own. CURLOPT_RESOLVE cannot do this: curl ignores a RESOLVE entry
     * when it parses the URL host as an address itself.
     *
     * @param  list{string}  $pinnedAddresses
     * @return array<string, mixed>
     */
    private function pinningOptions(string $url, array $pinnedAddresses): array
    {
        if ($pinnedAddresses === [] || ! defined('CURLOPT_CONNECT_TO')) {
            return [];
        }

        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        $port = parse_url($url, PHP_URL_PORT) ?? ($scheme === 'https' ? 443 : 80);
        $address = $pinnedAddresses[0];

        return [
            'curl' => [
                CURLOPT_CONNECT_TO => [sprintf('::%s:%d', $this->formatCurlAddress($address), $port)],
            ],
        ];
    }

    /**
     * curl needs brackets around an IPv6 pin (`::[2001:db8::1]:443`).
     */
    private function formatCurlAddress(string $address): string
    {
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return '['.$address.']';
        }

        return $address;
    }
}
