<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Services\IdTokenValidatorService;
use Qiick\Oidc\Testing\FakeIdentityProvider;

/*
 * Which JWKS keys may verify a token, and how strictly (RFC 7517, RFC 7518,
 * RFC 7515 §4.1.11). Each test serves its own JWKS, so the key material,
 * `kid`, `key_ops` and curve are exactly what an IdP could publish.
 */

const KEY_POLICY_JWKS_URI = 'https://idp.example.com/realms/test/key-policy-jwks';

const KEY_POLICY_NONCE = 'nonce-of-this-login';

/**
 * Serves $publishedKeys as the IdP's JWKS and allows $algorithm.
 *
 * @param  list<array<string, mixed>>  $publishedKeys
 */
function serveJwks(array $publishedKeys, string $algorithm): FakeIdentityProvider
{
    Http::fake([KEY_POLICY_JWKS_URI => Http::response(['keys' => $publishedKeys])]);
    $identityProvider = FakeIdentityProvider::fake();
    $identityProvider->withDiscovery(['jwks_uri' => KEY_POLICY_JWKS_URI, 'id_token_signing_alg_values_supported' => [$algorithm]]);
    Config::set('oidc.id_token.algorithms', [$algorithm]);

    return $identityProvider;
}

/**
 * @return array<string, mixed>
 */
function validateWithServedJwks(string $idToken): array
{
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
    $discovery = app(DiscoveryService::class)->discover($configuration);

    return app(IdTokenValidatorService::class)->validate($idToken, $discovery, $configuration, KEY_POLICY_NONCE);
}

/**
 * @param  array<string, mixed>  $extraMembers
 * @return array<string, mixed>
 */
function rsaJwk(OpenSSLAsymmetricKey $privateKey, string $keyId, array $extraMembers = []): array
{
    $rsaDetails = openssl_pkey_get_details($privateKey)['rsa'];

    return ['kty' => 'RSA', 'kid' => $keyId, 'n' => JWT::urlsafeB64Encode($rsaDetails['n']), 'e' => JWT::urlsafeB64Encode($rsaDetails['e']), ...$extraMembers];
}

/**
 * @return array<string, mixed>
 */
function ecJwk(OpenSSLAsymmetricKey $privateKey, string $keyId, string $curve): array
{
    $ecDetails = openssl_pkey_get_details($privateKey)['ec'];
    $coordinateBytes = $curve === 'P-256' ? 32 : 48;

    return [
        'kty' => 'EC',
        'kid' => $keyId,
        'crv' => $curve,
        'x' => JWT::urlsafeB64Encode(str_pad($ecDetails['x'], $coordinateBytes, "\0", STR_PAD_LEFT)),
        'y' => JWT::urlsafeB64Encode(str_pad($ecDetails['y'], $coordinateBytes, "\0", STR_PAD_LEFT)),
    ];
}

function rsaKey(int $bits): OpenSSLAsymmetricKey
{
    return openssl_pkey_new(['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
}

function ecKey(string $curve): OpenSSLAsymmetricKey
{
    return openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve === 'P-256' ? 'prime256v1' : 'secp384r1']);
}

/**
 * @param  array<string, mixed>  $extraHeader
 */
function signedWith(FakeIdentityProvider $identityProvider, OpenSSLAsymmetricKey $privateKey, string $algorithm, string $keyId, array $extraHeader = []): string
{
    $claims = $identityProvider->idTokenClaims(['nonce' => KEY_POLICY_NONCE]);

    if (! str_starts_with($algorithm, 'RS')) {
        return JWT::encode($claims, $privateKey, $algorithm, $keyId, $extraHeader);
    }

    // php-jwt refuses to sign with a short RSA key, so an IdP's short key is
    // simulated with OpenSSL directly.
    $signingInput = JWT::urlsafeB64Encode((string) json_encode(['typ' => 'JWT', 'alg' => $algorithm, 'kid' => $keyId, ...$extraHeader]))
        .'.'.JWT::urlsafeB64Encode((string) json_encode($claims));
    openssl_sign($signingInput, $signature, $privateKey, 'sha'.substr($algorithm, 2));

    return $signingInput.'.'.JWT::urlsafeB64Encode($signature);
}

/**
 * A PS256 token whose RSASSA-PSS signature uses $saltLength bytes of salt.
 */
function ps256SignedWithSalt(FakeIdentityProvider $identityProvider, OpenSSLAsymmetricKey $privateKey, string $keyId, int $saltLength): string
{
    openssl_pkey_export($privateKey, $privateKeyPem);
    $signingInput = JWT::urlsafeB64Encode((string) json_encode(['typ' => 'JWT', 'alg' => 'PS256', 'kid' => $keyId]))
        .'.'.JWT::urlsafeB64Encode((string) json_encode($identityProvider->idTokenClaims(['nonce' => KEY_POLICY_NONCE])));
    $signer = PublicKeyLoader::load($privateKeyPem)
        ->withPadding(RSA::SIGNATURE_PSS)
        ->withHash('sha256')
        ->withMGFHash('sha256')
        ->withSaltLength($saltLength);

    return $signingInput.'.'.JWT::urlsafeB64Encode($signer->sign($signingInput));
}

it('refuses an RSA key shorter than 2048 bits for every RSA algorithm', function (string $algorithm, int $bits): void {
    $privateKey = rsaKey($bits);
    $identityProvider = serveJwks([rsaJwk($privateKey, 'short-key')], $algorithm);

    validateWithServedJwks(signedWith($identityProvider, $privateKey, $algorithm, 'short-key'));
})->throws(InvalidTokenException::class, 'shorter than 2048 bits')->with([
    'RS256, 1024 bits' => ['RS256', 1024],
    'RS256, 2047 bits' => ['RS256', 2047],
    'RS512, 1024 bits' => ['RS512', 1024],
    'PS256, 1024 bits' => ['PS256', 1024],
    'PS256, 2040 bits' => ['PS256', 2040],
]);

it('accepts an RSA key of 2048 bits or more', function (string $algorithm, int $bits): void {
    $privateKey = rsaKey($bits);
    $identityProvider = serveJwks([rsaJwk($privateKey, 'long-key')], $algorithm);

    expect(validateWithServedJwks(signedWith($identityProvider, $privateKey, $algorithm, 'long-key'))['sub'])->toBe('fake-subject-1');
})->with([
    'RS256, 2048 bits' => ['RS256', 2048],
    'PS256, 3072 bits' => ['PS256', 3072],
]);

it('refuses a PS256 signature whose salt is not as long as the hash', function (int $saltLength): void {
    $privateKey = rsaKey(2048);
    $identityProvider = serveJwks([rsaJwk($privateKey, 'pss-key')], 'PS256');

    validateWithServedJwks(ps256SignedWithSalt($identityProvider, $privateKey, 'pss-key', $saltLength));
})->throws(InvalidTokenException::class, 'signature is invalid')->with([
    'no salt' => [0],
    'salt longer than the hash' => [64],
    'salt one byte short' => [31],
]);

it('accepts a PS256 signature with a 32-byte salt and leaves phpseclib as it found it', function (bool $isSaltLengthDiscoveryOn): void {
    $privateKey = rsaKey(2048);
    $identityProvider = serveJwks([rsaJwk($privateKey, 'pss-key')], 'PS256');
    $isSaltLengthDiscoveryOn ? RSA::enableSaltLengthDiscovery() : RSA::disableSaltLengthDiscovery();

    try {
        expect(validateWithServedJwks(ps256SignedWithSalt($identityProvider, $privateKey, 'pss-key', 32))['sub'])->toBe('fake-subject-1')
            ->and((new ReflectionProperty(RSA::class, 'autoSaltLength'))->getValue())->toBe($isSaltLengthDiscoveryOn);
    } finally {
        RSA::enableSaltLengthDiscovery();
    }
})->with(['discovery on (phpseclib default)' => true, 'discovery off' => false]);

it('refuses an EC key whose curve does not belong to the token algorithm', function (string $algorithm, string $keyCurve): void {
    $privateKey = ecKey($keyCurve);
    $identityProvider = serveJwks([ecJwk($privateKey, 'ec-key', $keyCurve)], $algorithm);

    validateWithServedJwks(signedWith($identityProvider, ecKey($algorithm === 'ES256' ? 'P-256' : 'P-384'), $algorithm, 'ec-key'));
})->throws(InvalidTokenException::class, 'No signing key in the JWKS matches')->with([
    'ES256 with a P-384 key' => ['ES256', 'P-384'],
    'ES384 with a P-256 key' => ['ES384', 'P-256'],
]);

it('accepts an EC key on the curve of the token algorithm', function (string $algorithm, string $curve): void {
    $privateKey = ecKey($curve);
    $identityProvider = serveJwks([ecJwk($privateKey, 'ec-key', $curve)], $algorithm);

    expect(validateWithServedJwks(signedWith($identityProvider, $privateKey, $algorithm, 'ec-key'))['sub'])->toBe('fake-subject-1');
})->with([
    'ES256 on P-256' => ['ES256', 'P-256'],
    'ES384 on P-384' => ['ES384', 'P-384'],
]);

it('refuses a token with a crit header, since the package understands no JWS extension', function (mixed $critical): void {
    $privateKey = rsaKey(2048);
    $identityProvider = serveJwks([rsaJwk($privateKey, 'rsa-key')], 'RS256');

    validateWithServedJwks(signedWith($identityProvider, $privateKey, 'RS256', 'rsa-key', ['crit' => $critical, 'exp' => 1]));
})->throws(InvalidTokenException::class, 'Token header [crit]')->with([
    'unknown extension' => [['exp']],
    'b64' => [['b64']],
    'empty list' => [[]],
    'not a list' => ['exp'],
]);

it('refuses a JWKS that publishes the token kid twice', function (): void {
    $privateKey = rsaKey(2048);
    $identityProvider = serveJwks([rsaJwk($privateKey, 'twin'), rsaJwk(rsaKey(2048), 'twin')], 'RS256');

    validateWithServedJwks(signedWith($identityProvider, $privateKey, 'RS256', 'twin'));
})->throws(InvalidTokenException::class, 'publishes the kid [twin] more than once');

it('ignores keys of another type when counting kid duplicates', function (): void {
    $privateKey = rsaKey(2048);
    $identityProvider = serveJwks([rsaJwk($privateKey, 'shared'), ecJwk(ecKey('P-256'), 'shared', 'P-256')], 'RS256');

    expect(validateWithServedJwks(signedWith($identityProvider, $privateKey, 'RS256', 'shared'))['sub'])->toBe('fake-subject-1');
});

it('refuses an encryption key that carries the token kid', function (): void {
    $privateKey = rsaKey(2048);
    $identityProvider = serveJwks([rsaJwk($privateKey, 'enc-key', ['use' => 'enc'])], 'RS256');

    validateWithServedJwks(signedWith($identityProvider, $privateKey, 'RS256', 'enc-key'));
})->throws(InvalidTokenException::class, 'No signing key in the JWKS matches');

it('honours key_ops when the JWKS sets it', function (mixed $keyOperations, bool $isAccepted): void {
    $privateKey = rsaKey(2048);
    $identityProvider = serveJwks([rsaJwk($privateKey, 'ops-key', ['key_ops' => $keyOperations])], 'RS256');
    $idToken = signedWith($identityProvider, $privateKey, 'RS256', 'ops-key');

    if ($isAccepted) {
        expect(validateWithServedJwks($idToken)['sub'])->toBe('fake-subject-1');

        return;
    }

    expect(fn () => validateWithServedJwks($idToken))->toThrow(InvalidTokenException::class, 'No signing key in the JWKS matches');
})->with([
    'verify' => [['verify'], true],
    'sign and verify' => [['sign', 'verify'], true],
    'encrypt only' => [['encrypt'], false],
    'empty' => [[], false],
    'not a list' => ['verify', false],
]);

it('skips a cached JWKS entry that is not a key object', function (): void {
    $privateKey = rsaKey(2048);
    $identityProvider = serveJwks([rsaJwk($privateKey, 'rsa-key')], 'RS256');
    $cacheKey = 'oidc:jwks:'.hash('sha256', KEY_POLICY_JWKS_URI);
    cache()->put($cacheKey, ['not-a-key', rsaJwk($privateKey, 'rsa-key')], 3600);
    // No refetch may rescue the lookup: the cached set alone must be read correctly.
    cache()->put("{$cacheKey}:refetch", true, 3600);

    expect(validateWithServedJwks(signedWith($identityProvider, $privateKey, 'RS256', 'rsa-key'))['sub'])->toBe('fake-subject-1');
});
