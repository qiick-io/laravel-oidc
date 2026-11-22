<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Services\IdTokenValidatorService;
use Qiick\Oidc\Testing\FakeIdentityProvider;

const EXPECTED_NONCE = 'nonce-of-this-login';

/**
 * @return array<string, mixed>
 */
function validateIdToken(string $idToken): array
{
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
    $discovery = app(DiscoveryService::class)->discover($configuration);

    return app(IdTokenValidatorService::class)->validate($idToken, $discovery, $configuration, EXPECTED_NONCE);
}

/**
 * @param  array<string, mixed>  $overrides
 */
function signedIdToken(FakeIdentityProvider $identityProvider, array $overrides = []): string
{
    return $identityProvider->sign($identityProvider->idTokenClaims(['nonce' => EXPECTED_NONCE, ...$overrides]));
}

/**
 * A token with the given header and claims and a garbage signature.
 *
 * @param  array<string, mixed>  $header
 * @param  array<string, mixed>  $claims
 */
function unsignedToken(array $header, array $claims, string $signature = ''): string
{
    return JWT::urlsafeB64Encode((string) json_encode($header)).'.'.JWT::urlsafeB64Encode((string) json_encode($claims)).'.'.$signature;
}

beforeEach(function (): void {
    $this->identityProvider = FakeIdentityProvider::fake();
});

it('accepts a valid id_token and returns its claims', function (): void {
    $claims = validateIdToken(signedIdToken($this->identityProvider, ['sub' => 'user-42']));

    expect($claims['sub'])->toBe('user-42')
        ->and($claims['email'])->toBe('sso.user@example.com');
});

it('refuses a token signed with another key that reuses the published kid', function (): void {
    $foreignKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $currentKeyId = $this->identityProvider->jwks()['keys'][0]['kid'];
    $forgedToken = $this->identityProvider->sign($this->identityProvider->idTokenClaims(['nonce' => EXPECTED_NONCE]), keyId: $currentKeyId, privateKey: $foreignKey);

    validateIdToken($forgedToken);
})->throws(InvalidTokenException::class, 'signature is invalid');

it('refuses a token whose payload was changed after signing', function (): void {
    [$header, , $signature] = explode('.', signedIdToken($this->identityProvider));
    $changedPayload = JWT::urlsafeB64Encode((string) json_encode($this->identityProvider->idTokenClaims(['nonce' => EXPECTED_NONCE, 'sub' => 'admin'])));

    validateIdToken("{$header}.{$changedPayload}.{$signature}");
})->throws(InvalidTokenException::class, 'signature is invalid');

it('refuses alg none, HMAC and algorithms not configured', function (string $algorithm): void {
    $claims = $this->identityProvider->idTokenClaims(['nonce' => EXPECTED_NONCE]);

    validateIdToken(unsignedToken(['alg' => $algorithm, 'typ' => 'JWT'], $claims, $algorithm === 'none' ? '' : 'c2lnbmF0dXJl'));
})->throws(InvalidTokenException::class, 'algorithm is not allowed')->with(['none', 'None', 'HS256', 'RS384', 'ES256']);

it('refuses an HS256 token signed with the client secret even when HS256 is configured', function (): void {
    Config::set('oidc.id_token.algorithms', ['RS256', 'HS256']);
    $token = JWT::encode($this->identityProvider->idTokenClaims(['nonce' => EXPECTED_NONCE]), str_repeat('client-secret-', 4), 'HS256');

    validateIdToken($token);
})->throws(InvalidTokenException::class, 'algorithm is not allowed');

it('refuses malformed tokens', function (string $token): void {
    validateIdToken($token);
})->throws(InvalidTokenException::class)->with([
    'empty' => '',
    'two segments' => 'a.b',
    'encrypted (JWE)' => 'a.b.c.d.e',
    'header not json' => 'bm90LWpzb24.e30.c2ln',
]);

it('refuses a wrong issuer', function (): void {
    validateIdToken(signedIdToken($this->identityProvider, ['iss' => 'https://evil.example.com/realms/test']));
})->throws(InvalidTokenException::class, '[iss]');

it('refuses a token for another client', function (mixed $audience): void {
    validateIdToken(signedIdToken($this->identityProvider, ['aud' => $audience]));
})->throws(InvalidTokenException::class, '[aud]')->with([
    'other client' => 'other-app',
    'missing' => null,
    'list without us' => [['other-app', 'account']],
    'not strings' => [[42]],
]);

it('refuses an untrusted extra audience', function (): void {
    validateIdToken(signedIdToken($this->identityProvider, ['aud' => ['laravel-app', 'other-app'], 'azp' => 'laravel-app']));
})->throws(InvalidTokenException::class, 'untrusted audience');

it('accepts a trusted extra audience only with azp set to the client id', function (): void {
    Config::set('oidc.id_token.trusted_audiences', ['account']);

    expect(validateIdToken(signedIdToken($this->identityProvider, ['aud' => ['laravel-app', 'account'], 'azp' => 'laravel-app']))['sub'])
        ->toBe('fake-subject-1')
        ->and(fn () => validateIdToken(signedIdToken($this->identityProvider, ['aud' => ['laravel-app', 'account']])))
        ->toThrow(InvalidTokenException::class, '[azp]');
});

it('refuses an azp that is not the client id', function (): void {
    validateIdToken(signedIdToken($this->identityProvider, ['azp' => 'other-app']));
})->throws(InvalidTokenException::class, '[azp]');

it('refuses an expired token, with the configured leeway', function (): void {
    $now = Date::now()->getTimestamp();

    expect(validateIdToken(signedIdToken($this->identityProvider, ['iat' => $now - 600, 'exp' => $now - 30]))['sub'])->toBe('fake-subject-1')
        ->and(fn () => validateIdToken(signedIdToken($this->identityProvider, ['iat' => $now - 600, 'exp' => $now - 61])))
        ->toThrow(InvalidTokenException::class, 'expired');
});

it('refuses a token issued in the future', function (array $overrides): void {
    $now = Date::now()->getTimestamp();

    validateIdToken(signedIdToken($this->identityProvider, [...$overrides, 'iat' => $now + 120, 'exp' => $now + 600]));
})->throws(InvalidTokenException::class, 'not valid yet')->with([
    'without nbf' => [[]],
    'with nbf in the past' => [['nbf' => 1]],
]);

it('refuses a token without exp or iat', function (string $claim): void {
    $claims = $this->identityProvider->idTokenClaims(['nonce' => EXPECTED_NONCE]);
    unset($claims[$claim]);

    validateIdToken($this->identityProvider->sign($claims));
})->throws(InvalidTokenException::class, 'no numeric')->with(['exp', 'iat']);

it('refuses a wrong or missing nonce', function (mixed $nonce): void {
    $claims = $this->identityProvider->idTokenClaims(['nonce' => $nonce]);

    validateIdToken($this->identityProvider->sign(array_filter($claims, fn (mixed $value): bool => $value !== null)));
})->throws(InvalidTokenException::class, '[nonce]')->with(['another-login', null, '']);

it('refuses a missing, empty or oversized sub', function (mixed $subject): void {
    validateIdToken(signedIdToken($this->identityProvider, ['sub' => $subject]));
})->throws(InvalidTokenException::class, '[sub]')->with([null, '', 42, str_repeat('a', 256)]);

it('accepts a sub of exactly 255 ASCII characters', function (): void {
    $subject = str_repeat('a', 255);

    expect(validateIdToken(signedIdToken($this->identityProvider, ['sub' => $subject]))['sub'])->toBe($subject);
});

it('refuses a sub with leading or trailing whitespace', function (string $subject): void {
    validateIdToken(signedIdToken($this->identityProvider, ['sub' => $subject]));
})->throws(InvalidTokenException::class, '[sub] has leading or trailing whitespace')->with([' AbcSubject', 'AbcSubject ', "AbcSubject\t", "\nAbcSubject", ' ']);

it('caches the JWKS and refetches it once when the IdP rotates its key', function (): void {
    validateIdToken(signedIdToken($this->identityProvider));
    validateIdToken(signedIdToken($this->identityProvider));
    expect($this->identityProvider->jwksRequestCount)->toBe(1);

    $this->identityProvider->rotateSigningKey(isPreviousKeyRetired: true);

    expect(validateIdToken(signedIdToken($this->identityProvider))['sub'])->toBe('fake-subject-1')
        ->and($this->identityProvider->jwksRequestCount)->toBe(2);
});

it('rate limits JWKS refetches triggered by unknown kids', function (): void {
    validateIdToken(signedIdToken($this->identityProvider));
    $claims = $this->identityProvider->idTokenClaims(['nonce' => EXPECTED_NONCE]);

    foreach (['forged-1', 'forged-2', 'forged-3'] as $forgedKeyId) {
        expect(fn () => validateIdToken($this->identityProvider->sign($claims, keyId: $forgedKeyId, privateKey: openssl_pkey_new(['private_key_bits' => 2048]) ?: null)))
            ->toThrow(InvalidTokenException::class, 'No signing key');
    }

    expect($this->identityProvider->jwksRequestCount)->toBe(2);
});

it('uses the only signing key when the token has no kid, and refuses ambiguity', function (): void {
    $tokenWithoutKeyId = $this->identityProvider->sign($this->identityProvider->idTokenClaims(['nonce' => EXPECTED_NONCE]), isKeyIdOmitted: true);

    expect(validateIdToken($tokenWithoutKeyId)['sub'])->toBe('fake-subject-1');

    $this->identityProvider->rotateSigningKey();
    cache()->flush();

    expect(fn () => validateIdToken($tokenWithoutKeyId))->toThrow(InvalidTokenException::class, 'No signing key');
});

it('does not leak its clock or leeway into php-jwt', function (): void {
    JWT::$leeway = 7;
    JWT::$timestamp = null;

    validateIdToken(signedIdToken($this->identityProvider));

    expect(JWT::$leeway)->toBe(7)->and(JWT::$timestamp)->toBeNull();

    JWT::$leeway = 0;
});

/*
 * S1: at_hash is OPTIONAL in the code flow; when present it must match
 * (OIDC Core 3.1.3.8 / 3.2.2.9).
 */

function accessTokenHash(string $accessToken, string $hashAlgorithm = 'sha256'): string
{
    $digest = hash($hashAlgorithm, $accessToken, true);

    return JWT::urlsafeB64Encode(substr($digest, 0, (int) (strlen($digest) / 2)));
}

it('accepts an id_token whose at_hash matches the access_token', function (): void {
    $accessToken = 'access-token-for-at-hash';
    $idToken = signedIdToken($this->identityProvider, ['at_hash' => accessTokenHash($accessToken)]);
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
    $discovery = app(DiscoveryService::class)->discover($configuration);

    $claims = app(IdTokenValidatorService::class)->validate(
        $idToken,
        $discovery,
        $configuration,
        EXPECTED_NONCE,
        $accessToken,
    );

    expect($claims['at_hash'])->toBe(accessTokenHash($accessToken));
});

it('refuses a mismatched or malformed at_hash', function (mixed $accessTokenHash, string $accessToken): void {
    $idToken = signedIdToken($this->identityProvider, ['at_hash' => $accessTokenHash]);
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
    $discovery = app(DiscoveryService::class)->discover($configuration);

    app(IdTokenValidatorService::class)->validate(
        $idToken,
        $discovery,
        $configuration,
        EXPECTED_NONCE,
        $accessToken,
    );
})->throws(InvalidTokenException::class, 'at_hash')->with([
    'wrong hash' => [accessTokenHash('other-token'), 'access-token-for-at-hash'],
    'not a string' => [42, 'access-token-for-at-hash'],
]);

it('refuses an empty at_hash as malformed', function (): void {
    $idToken = signedIdToken($this->identityProvider, ['at_hash' => '']);
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
    $discovery = app(DiscoveryService::class)->discover($configuration);

    app(IdTokenValidatorService::class)->validate(
        $idToken,
        $discovery,
        $configuration,
        EXPECTED_NONCE,
        'access-token-for-at-hash',
    );
})->throws(InvalidTokenException::class, 'at_hash] is malformed');

it('refuses at_hash when no access_token was issued', function (): void {
    $idToken = signedIdToken($this->identityProvider, ['at_hash' => accessTokenHash('token')]);
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
    $discovery = app(DiscoveryService::class)->discover($configuration);

    // Omit the access token so the default empty string is what the check sees.
    app(IdTokenValidatorService::class)->validate($idToken, $discovery, $configuration, EXPECTED_NONCE);
})->throws(InvalidTokenException::class, 'at_hash] is present but no access_token');

it('accepts an id_token that omits at_hash in the code flow', function (): void {
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
    $discovery = app(DiscoveryService::class)->discover($configuration);

    $claims = app(IdTokenValidatorService::class)->validate(
        signedIdToken($this->identityProvider),
        $discovery,
        $configuration,
        EXPECTED_NONCE,
        'access-token-present-but-unused',
    );

    expect($claims)->not->toHaveKey('at_hash');
});

it('selects the at_hash digest algorithm from the JWS alg', function (string $algorithm, string $hashAlgorithm, string $keyType): void {
    Config::set('oidc.id_token.algorithms', ['RS256', 'RS384', 'ES256']);
    cache()->flush();

    if ($keyType === 'EC') {
        $this->identityProvider->rotateSigningKey(isPreviousKeyRetired: true, keyType: 'EC');
    }

    $this->identityProvider->withDiscovery([
        'id_token_signing_alg_values_supported' => ['RS256', 'RS384', 'ES256'],
    ]);

    $accessToken = 'access-token-for-alg-'.$algorithm;
    $matchingHash = accessTokenHash($accessToken, $hashAlgorithm);
    $wrongHash = accessTokenHash($accessToken, $hashAlgorithm === 'sha384' ? 'sha256' : 'sha384');
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
    $discovery = app(DiscoveryService::class)->discover($configuration);

    $acceptedClaims = app(IdTokenValidatorService::class)->validate(
        $this->identityProvider->sign(
            $this->identityProvider->idTokenClaims(['nonce' => EXPECTED_NONCE, 'at_hash' => $matchingHash]),
            algorithm: $algorithm,
        ),
        $discovery,
        $configuration,
        EXPECTED_NONCE,
        $accessToken,
    );

    expect($acceptedClaims['at_hash'])->toBe($matchingHash);

    expect(fn () => app(IdTokenValidatorService::class)->validate(
        $this->identityProvider->sign(
            $this->identityProvider->idTokenClaims(['nonce' => EXPECTED_NONCE, 'at_hash' => $wrongHash]),
            algorithm: $algorithm,
        ),
        $discovery,
        $configuration,
        EXPECTED_NONCE,
        $accessToken,
    ))->toThrow(InvalidTokenException::class, 'at_hash');
})->with([
    'RS384 uses sha384' => ['RS384', 'sha384', 'RSA'],
    'ES256 uses sha256' => ['ES256', 'sha256', 'EC'],
]);

it('refuses at_hash when the JWS alg is missing or has no hash mapping', function (array $header): void {
    $accessToken = 'access-token-for-missing-alg';
    $accessTokenHash = accessTokenHash($accessToken);
    $idToken = unsignedToken($header, ['at_hash' => $accessTokenHash], 'sig');

    // JwtValidatorService is final; reach the at_hash alg map after shared JWT checks.
    $assertAccessTokenHash = new ReflectionMethod(IdTokenValidatorService::class, 'assertAccessTokenHash');

    expect(fn () => $assertAccessTokenHash->invoke(
        app(IdTokenValidatorService::class),
        $idToken,
        $accessToken,
        $accessTokenHash,
    ))->toThrow(InvalidTokenException::class, 'cannot be checked for this signing algorithm');
})->with([
    'alg absent' => [['typ' => 'JWT']],
    'alg unsupported' => [['alg' => 'HS256', 'typ' => 'JWT']],
]);
