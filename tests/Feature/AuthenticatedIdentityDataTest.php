<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Data\ProviderConfigurationData;

/**
 * Builds an identity from claims and an id_token whose header is `$header`
 * (the signature is not checked here: the validator already did).
 *
 * @param  array<string, mixed>  $claims
 * @param  array<string, mixed>|string  $header
 */
function identityWithIdTokenHeader(array $claims = [], array|string $header = ['alg' => 'RS256']): AuthenticatedIdentityData
{
    $encodedHeader = JWT::urlsafeB64Encode(is_string($header) ? $header : json_encode($header, JSON_THROW_ON_ERROR));

    return new AuthenticatedIdentityData('https://idp.example.com', 'subject', $claims, "{$encodedHeader}.payload.signature", 'access-token', null);
}

it('treats the requested authentication context as met unless told otherwise', function (): void {
    expect(identityWithIdTokenHeader()->isRequestedAuthenticationContextMet)->toBeTrue();
});

it('reads acr only as a non-empty string', function (mixed $acr, ?string $expected): void {
    expect(identityWithIdTokenHeader(['acr' => $acr])->acr())->toBe($expected);
})->with([
    'a value' => ['urn:qiick:loa:mfa', 'urn:qiick:loa:mfa'],
    'empty' => ['', null],
    'not a string' => [2, null],
]);

it('reads amr only as a list of non-empty strings', function (mixed $amr, ?array $expected): void {
    expect(identityWithIdTokenHeader(['amr' => $amr])->amr())->toBe($expected);
})->with([
    'a list' => [['pwd', 'otp'], ['pwd', 'otp']],
    'an empty list' => [[], []],
    'an empty member first' => [['', 'otp'], null],
    'an empty member last' => [['pwd', ''], null],
    'a number member' => [['pwd', 1], null],
    'not a list' => ['mfa', null],
]);

it('reads the signing algorithm from the id_token header', function (array|string $header, ?string $expected): void {
    expect(identityWithIdTokenHeader(header: $header)->idTokenAlgorithm())->toBe($expected);
})->with([
    'an algorithm' => [['alg' => 'ES256'], 'ES256'],
    'an empty algorithm' => [['alg' => ''], null],
    'no algorithm' => [['typ' => 'JWT'], null],
    'a number algorithm' => [['alg' => 256], null],
    'a header that is not an object' => ['"RS256"', null],
    'a header that is not JSON' => ['{', null],
]);

it('reads no algorithm from a token that is not three segments', function (string $idToken): void {
    $identity = new AuthenticatedIdentityData('https://idp.example.com', 'subject', [], $idToken, 'access-token', null);

    expect($identity->idTokenAlgorithm())->toBeNull();
})->with(function (): array {
    $header = JWT::urlsafeB64Encode('{"alg":"RS256"}');

    return ['two segments' => ["{$header}.payload"], 'four segments' => ["{$header}.payload.signature.extra"]];
});

it('treats a client without a secret, or with an empty one, as public', function (?string $clientSecret, bool $isPublic): void {
    $configuration = new ProviderConfigurationData('https://idp.example.com', 'client', $clientSecret, 'https://app.example.com/callback', ['openid']);

    expect($configuration->isPublicClient())->toBe($isPublic);
})->with([
    'no secret' => [null, true],
    'an empty secret' => ['', true],
    'a secret' => ['secret', false],
]);
