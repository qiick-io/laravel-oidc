<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Config;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Services\IdTokenValidatorService;
use Qiick\Oidc\Testing\FakeIdentityProvider;

/*
 * Every algorithm in JwtValidatorService::SUPPORTED_ALGORITHMS must verify a
 * real signature end to end: an algorithm the package declares but cannot
 * verify would only fail closed at the first login.
 */

/**
 * Signs an id_token with $algorithm, with the key type and curve it needs,
 * and validates it with only that algorithm allowed on both sides.
 *
 * @return array<string, mixed>
 */
function validateIdTokenSignedWith(string $algorithm, string $keyType = 'RSA', string $curve = 'P-256', ?string $signingAlgorithm = null): array
{
    $identityProvider = FakeIdentityProvider::fake();
    Config::set('oidc.id_token.algorithms', [$algorithm]);
    $identityProvider->withDiscovery(['id_token_signing_alg_values_supported' => [$algorithm]]);

    if ($keyType === 'EC') {
        $identityProvider->rotateSigningKey(isPreviousKeyRetired: true, keyType: 'EC', curve: $curve);
    }

    $idToken = $identityProvider->sign(
        $identityProvider->idTokenClaims(['nonce' => 'nonce-of-this-login']),
        algorithm: $signingAlgorithm ?? $algorithm,
    );
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
    $discovery = app(DiscoveryService::class)->discover($configuration);

    return app(IdTokenValidatorService::class)->validate($idToken, $discovery, $configuration, 'nonce-of-this-login');
}

it('verifies every supported algorithm', function (string $algorithm, string $keyType, string $curve): void {
    expect(validateIdTokenSignedWith($algorithm, $keyType, $curve)['sub'])->toBe('fake-subject-1');
})->with([
    'RS256' => ['RS256', 'RSA', 'P-256'],
    'RS384' => ['RS384', 'RSA', 'P-256'],
    'RS512' => ['RS512', 'RSA', 'P-256'],
    'PS256' => ['PS256', 'RSA', 'P-256'],
    'ES256' => ['ES256', 'EC', 'P-256'],
    'ES384' => ['ES384', 'EC', 'P-384'],
]);

it('refuses an ES256 token signed with a P-384 key', function (): void {
    validateIdTokenSignedWith('ES256', 'EC', 'P-384');
})->throws(InvalidTokenException::class, 'No signing key in the JWKS matches');

it('refuses a PS256 signature presented as RS256', function (): void {
    validateIdTokenSignedWith('RS256', signingAlgorithm: 'PS256');
})->throws(InvalidTokenException::class);

it('publishes an EC key with the curve, algorithm and coordinate length of its curve', function (string $curve, string $algorithm, int $coordinateBytes): void {
    $identityProvider = FakeIdentityProvider::fake();
    $identityProvider->rotateSigningKey(isPreviousKeyRetired: true, keyType: 'EC', curve: $curve);

    $publishedKey = $identityProvider->jwks()['keys'][0];

    expect([$publishedKey['kty'], $publishedKey['crv'], $publishedKey['alg']])->toBe(['EC', $curve, $algorithm])
        ->and(strlen((string) base64_decode(strtr($publishedKey['x'], '-_', '+/'), true)))->toBe($coordinateBytes)
        ->and(strlen((string) base64_decode(strtr($publishedKey['y'], '-_', '+/'), true)))->toBe($coordinateBytes);
})->with([
    'P-256' => ['P-256', 'ES256', 32],
    'P-384' => ['P-384', 'ES384', 48],
]);

it('refuses a curve the fake cannot sign with', function (): void {
    FakeIdentityProvider::fake()->rotateSigningKey(keyType: 'EC', curve: 'P-521');
})->throws(RuntimeException::class, 'Unsupported test curve [P-521].');
