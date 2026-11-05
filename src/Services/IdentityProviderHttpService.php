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
 * through the SSRF guard, pins the checked addresses, refuses redirects and
 * expects a JSON object back.
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
     * @return array<string, mixed>
     *
     * @throws IdentityProviderRequestException
     */
    public function getJson(string $url): array
    {
        return $this->send($url, fn (PendingRequest $request): Response => $request->get($url));
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
     * Pins the host to the addresses the guard checked (CURLOPT_RESOLVE), so a
     * DNS answer that changes between the check and the request cannot send
     * the call to an internal address.
     *
     * @param  list<string>  $pinnedAddresses
     * @return array<string, mixed>
     */
    private function pinningOptions(string $url, array $pinnedAddresses): array
    {
        $host = parse_url($url, PHP_URL_HOST);

        if ($pinnedAddresses === [] || ! is_string($host) || ! defined('CURLOPT_RESOLVE')) {
            return [];
        }

        $port = parse_url($url, PHP_URL_PORT) ?? (strtolower((string) parse_url($url, PHP_URL_SCHEME)) === 'https' ? 443 : 80);
        $address = $pinnedAddresses[0];
        $formattedAddress = str_contains($address, ':') ? "[{$address}]" : $address;

        return ['curl' => [CURLOPT_RESOLVE => ["{$host}:{$port}:{$formattedAddress}"]]];
    }
}
