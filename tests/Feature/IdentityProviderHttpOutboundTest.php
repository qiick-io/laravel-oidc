<?php

declare(strict_types=1);

use GuzzleHttp\Promise\Create as PromiseCreate;
use GuzzleHttp\Psr7\Response as Psr7Response;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Services\IdentityProviderHttpService;
use Qiick\Outbound\Http\OutboundHttpException;
use Qiick\Outbound\Http\OutboundHttpLimits;
use Qiick\Outbound\Http\OutboundHttpStackData;
use Qiick\Outbound\Ssrf\UrlGuardOptions;
use Qiick\Outbound\Testing\FakeHostResolver;
use Qiick\Outbound\Testing\FakeOutboundHttpFactory;

function outboundIdpHttp(
    FakeHostResolver $resolver = new FakeHostResolver,
    int $maxResponseBytes = 1_048_576,
    ?Closure $fakeResponse = null,
    int $timeoutSeconds = 5,
    int $connectTimeoutSeconds = 10,
    ?OutboundHttpLimits $limits = null,
): IdentityProviderHttpService {
    $outbound = OutboundHttpStackData::make(
        $resolver,
        limits: $limits ?? new OutboundHttpLimits,
        httpFactory: $fakeResponse === null ? app(HttpFactory::class) : FakeOutboundHttpFactory::fake($fakeResponse),
    );

    return new IdentityProviderHttpService(
        $outbound->client,
        new UrlGuardOptions(httpsOnly: true, allowPrivateHosts: false),
        timeoutSeconds: $timeoutSeconds,
        connectTimeoutSeconds: $connectTimeoutSeconds,
        maxResponseBytes: $maxResponseBytes,
    );
}

it('maps UnsafeUrl refusals to IdentityProviderRequestException without calling the IdP', function (): void {
    Http::fake();

    expect(fn () => outboundIdpHttp()->getJson('https://127.0.0.1/token'))
        ->toThrow(IdentityProviderRequestException::class, 'not allowed');

    Http::assertNothingSent();
});

it('maps every UnsafeUrl reason to the public OIDC exception wording', function (string $url, array $answers, string $fullMessage): void {
    Http::fake();

    expect(fn () => outboundIdpHttp(new FakeHostResolver(answers: $answers))->getJson($url))
        ->toThrow(fn (IdentityProviderRequestException $exception) => expect($exception->getMessage())->toBe($fullMessage));

    Http::assertNothingSent();
})->with([
    'plain http' => ['http://idp.example.com/token', [], 'OIDC endpoints must use https.'],
    'credentials' => ['https://user:secret@idp.example.com/token', [], 'OIDC endpoints must not contain credentials.'],
    'not absolute' => ['idp.example.com/token', [], 'OIDC endpoint is not an absolute URL.'],
    'unresolved' => ['https://idp.example.com/token', [], 'OIDC endpoint host [idp.example.com] does not resolve.'],
    'disallowed address' => [
        'https://idp.example.com/token',
        ['idp.example.com' => ['10.0.0.5']],
        'OIDC endpoint host [idp.example.com] resolves to a disallowed address. Set OIDC_ALLOW_PRIVATE_HOSTS=true only for an IdP on a private network.',
    ],
    'invalid spelling' => ['https://[not:an:ip]/token', [], 'OIDC endpoint host [[not:an:ip]] is invalid.'],
    'private loopback literal' => [
        'https://127.0.0.1/token',
        [],
        'OIDC endpoint host [127.0.0.1] is not allowed (private, loopback or metadata address). Set OIDC_ALLOW_PRIVATE_HOSTS=true only for an IdP on a private network.',
    ],
]);

it('includes a sanitised OAuth error code on HTTP failures', function (): void {
    $http = outboundIdpHttp(
        new FakeHostResolver(answers: ['idp.example.com' => ['93.184.216.34']]),
        fakeResponse: function () {
            return PromiseCreate::promiseFor(new Psr7Response(
                400,
                ['Content-Type' => 'application/json'],
                '{"error":"invalid_grant","error_description":"secret"}',
            ));
        },
    );

    expect(fn () => $http->getJson('https://idp.example.com/token'))
        ->toThrow(IdentityProviderRequestException::class, 'HTTP 400 (invalid_grant)');
});

it('does not echo a non-string OAuth error field', function (): void {
    $http = outboundIdpHttp(
        new FakeHostResolver(answers: ['idp.example.com' => ['93.184.216.34']]),
        fakeResponse: function () {
            return PromiseCreate::promiseFor(new Psr7Response(
                500,
                ['Content-Type' => 'application/json'],
                '{"error":{"nested":true}}',
            ));
        },
    );

    expect(fn () => $http->getJson('https://idp.example.com/token'))
        ->toThrow(fn (IdentityProviderRequestException $exception) => expect($exception->getMessage())
            ->toBe('OIDC request to [idp.example.com] failed with HTTP 500.'));
});

it('refuses an oversized JSON response through the size limit', function (): void {
    $http = outboundIdpHttp(
        new FakeHostResolver(answers: ['idp.example.com' => ['93.184.216.34']]),
        maxResponseBytes: 32,
        fakeResponse: function () {
            return PromiseCreate::promiseFor(new Psr7Response(
                200,
                ['Content-Type' => 'application/json'],
                '{"payload":"'.str_repeat('a', 64).'"}',
            ));
        },
    );

    expect(fn () => $http->getJson('https://idp.example.com/token'))
        ->toThrow(IdentityProviderRequestException::class, 'connection error');
});

it('does not follow redirects from the IdP', function (): void {
    Http::fake([
        'https://idp.example.com/token' => Http::response('', 302, ['Location' => 'https://evil.example.com/']),
    ]);

    expect(fn () => outboundIdpHttp(
        new FakeHostResolver(answers: ['idp.example.com' => ['93.184.216.34']]),
    )->getJson('https://idp.example.com/token'))
        ->toThrow(IdentityProviderRequestException::class, 'HTTP 302');
});

it('posts form bodies and returns a JSON object', function (): void {
    $seenBody = null;

    $http = outboundIdpHttp(
        new FakeHostResolver(answers: ['idp.example.com' => ['93.184.216.34']]),
        fakeResponse: function (Request $request) use (&$seenBody) {
            $seenBody = $request->body();

            return PromiseCreate::promiseFor(new Psr7Response(
                200,
                ['Content-Type' => 'application/json'],
                '{"access_token":"t","token_type":"Bearer"}',
            ));
        },
    );

    expect($http->postForm('https://idp.example.com/token', ['grant_type' => 'authorization_code', 'code' => 'abc']))
        ->toBe(['access_token' => 't', 'token_type' => 'Bearer'])
        ->and($seenBody)->toContain('grant_type=authorization_code')
        ->and($seenBody)->toContain('code=abc');
});

it('wraps OutboundHttpException as a connection error', function (): void {
    $http = outboundIdpHttp(
        new FakeHostResolver(answers: ['idp.example.com' => ['93.184.216.34']]),
        fakeResponse: function () {
            throw new OutboundHttpException('Response exceeds max_response_bytes.');
        },
    );

    expect(fn () => $http->getJson('https://idp.example.com/token'))
        ->toThrow(IdentityProviderRequestException::class, 'connection error');
});

it('refuses a non-object JSON payload', function (): void {
    $http = outboundIdpHttp(
        new FakeHostResolver(answers: ['idp.example.com' => ['93.184.216.34']]),
        fakeResponse: function () {
            return PromiseCreate::promiseFor(new Psr7Response(200, ['Content-Type' => 'application/json'], '["list"]'));
        },
    );

    expect(fn () => $http->getJson('https://idp.example.com/token'))
        ->toThrow(IdentityProviderRequestException::class, 'not a JSON object');
});

it('maps timeout 0 onto the literal 86400 ceiling, not only the named constant', function (): void {
    expect(IdentityProviderHttpService::resolveTimeoutSeconds(0))->toBe(86400);

    $seenTimeout = null;

    $http = outboundIdpHttp(
        new FakeHostResolver(answers: ['idp.example.com' => ['93.184.216.34']]),
        fakeResponse: function (Request $request, array $options) use (&$seenTimeout) {
            $seenTimeout = $options['timeout'] ?? null;

            return PromiseCreate::promiseFor(new Psr7Response(200, ['Content-Type' => 'application/json'], '{"ok":true}'));
        },
        timeoutSeconds: 0,
        connectTimeoutSeconds: 0,
        limits: new OutboundHttpLimits(
            maxTimeoutSeconds: 86400,
            maxConnectTimeoutSeconds: 86400,
            totalDeadlineSeconds: 86400,
        ),
    );

    expect($http->getJson('https://idp.example.com/token'))->toBe(['ok' => true])
        ->and($seenTimeout)->toBeGreaterThanOrEqual(86399)
        ->and($seenTimeout)->toBeLessThanOrEqual(86400);
});
