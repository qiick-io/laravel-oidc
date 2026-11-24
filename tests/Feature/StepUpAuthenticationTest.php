<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Services\AuthorizationCodeFlowService;
use Qiick\Oidc\Services\MultiFactorClaimService;
use Qiick\Oidc\Testing\FakeIdentityProvider;

/*
 * Standards review S2: `max_age` with the `auth_time` check (OIDC Core
 * 3.1.2.1 and 3.1.3.7 step 13), and the `acr` an IdP returns against the
 * `acr` the login asked for (3.1.2.1 `acr_values`, 5.5.1.1 `claims`).
 */

/**
 * Logs in through the fake IdP with $additionalParameters on the
 * authorization request and $claims in the id_token.
 *
 * @param  array<string, string>  $additionalParameters
 * @param  array<string, mixed>  $claims
 */
function stepUpLogin(FakeIdentityProvider $identityProvider, array $additionalParameters = [], array $claims = []): AuthenticatedIdentityData
{
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session, $additionalParameters), $claims);

    return app(AuthorizationCodeFlowService::class)->handleCallback(browserRequest($callbackUrl, $session));
}

function isMultiFactorProven(AuthenticatedIdentityData $identity): bool
{
    return app(MultiFactorClaimService::class)->isSatisfied($identity);
}

beforeEach(function (): void {
    Date::setTestNow(Date::now()->startOfSecond());
});

it('sends the configured max_age and nothing without it', function (): void {
    FakeIdentityProvider::fake();
    $withoutMaxAge = startLogin(browserSession());
    Config::set('oidc.mfa.max_age', 300);

    expect(queryParameters($withoutMaxAge))->not->toHaveKey('max_age')
        ->and(queryParameters(startLogin(browserSession()))['max_age'])->toBe('300');
});

it('refuses an id_token without auth_time when max_age was sent', function (): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa.max_age' => 300]);

    stepUpLogin($identityProvider, claims: ['auth_time' => null]);
})->throws(InvalidTokenException::class, 'id_token has no numeric [auth_time], which max_age requires.');

it('refuses an authentication older than max_age plus the leeway, and accepts one within', function (int $secondsAgo, bool $isAccepted): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa.max_age' => 300, 'id_token.leeway' => 60]);
    $login = fn () => stepUpLogin($identityProvider, claims: ['auth_time' => Date::now()->getTimestamp() - $secondsAgo]);

    if ($isAccepted) {
        expect($login()->subject)->toBe('fake-subject-1');

        return;
    }

    expect($login)->toThrow(InvalidTokenException::class, 'id_token [auth_time] is older than max_age allows.');
})->with([
    'fresh' => [10, true],
    'at max_age' => [300, true],
    'at max_age plus the leeway' => [360, true],
    'one second past the leeway' => [361, false],
    'an hour ago' => [3600, false],
]);

it('accepts an id_token without auth_time when no max_age was sent', function (): void {
    $identityProvider = FakeIdentityProvider::fake();

    expect(stepUpLogin($identityProvider, claims: ['auth_time' => null])->subject)->toBe('fake-subject-1');
});

it('takes max_age from the authorization request over the configured one', function (): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa.max_age' => 3600]);
    $authorizationUrl = startLogin(browserSession(), ['max_age' => '60']);

    expect(queryParameters($authorizationUrl)['max_age'])->toBe('60')
        ->and(fn () => stepUpLogin($identityProvider, ['max_age' => '60'], ['auth_time' => Date::now()->getTimestamp() - 600]))
        ->toThrow(InvalidTokenException::class, 'older than max_age');
});

it('proves MFA through the requested acr only when the IdP returns it', function (array $claims, bool $isProven): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa.request_acr_values' => 'urn:qiick:loa:mfa']);

    $identity = stepUpLogin($identityProvider, ['acr_values' => 'urn:qiick:loa:mfa'], $claims);

    expect(isMultiFactorProven($identity))->toBe($isProven);
})->with([
    'requested acr returned' => [['acr' => 'urn:qiick:loa:mfa'], true],
    'lower acr returned' => [['acr' => 'urn:qiick:loa:pwd', 'amr' => ['mfa']], false],
    'acr missing' => [['amr' => ['mfa']], false],
]);

it('keeps amr proving MFA when no acr was requested', function (): void {
    $identityProvider = FakeIdentityProvider::fake();

    expect(isMultiFactorProven(stepUpLogin($identityProvider, claims: ['amr' => ['mfa']])))->toBeTrue();
});

it('refuses a missing or lower acr when require_requested_acr is on', function (array $claims): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa.require_requested_acr' => true]);

    stepUpLogin($identityProvider, ['acr_values' => 'gold silver'], $claims);
})->throws(InvalidTokenException::class, 'id_token [acr] is not one of the requested values.')->with([
    'missing' => [[]],
    'lower' => [['acr' => 'bronze']],
    'not a string' => [['acr' => ['gold']]],
]);

it('accepts any requested acr when require_requested_acr is on', function (): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa.require_requested_acr' => true, 'mfa.acr_values' => ['silver']]);

    $identity = stepUpLogin($identityProvider, ['acr_values' => 'gold silver'], ['acr' => 'silver']);

    expect($identity->acr())->toBe('silver')->and(isMultiFactorProven($identity))->toBeTrue();
});

it('applies the same rules to an acr requested through the claims parameter', function (string $claimsParameter, array $claims, bool $isAccepted): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa.require_requested_acr' => true]);
    $login = fn () => stepUpLogin($identityProvider, ['claims' => $claimsParameter], $claims);

    if ($isAccepted) {
        expect($login()->subject)->toBe('fake-subject-1');

        return;
    }

    expect($login)->toThrow(InvalidTokenException::class, 'id_token [acr] is not one of the requested values.');
})->with([
    'essential with values, met' => ['{"id_token":{"acr":{"essential":true,"values":["gold"]}}}', ['acr' => 'gold'], true],
    'essential with values, lower' => ['{"id_token":{"acr":{"essential":true,"values":["gold"]}}}', ['acr' => 'bronze'], false],
    'single value, met' => ['{"id_token":{"acr":{"value":"gold"}}}', ['acr' => 'gold'], true],
    'essential without values, present' => ['{"id_token":{"acr":{"essential":true}}}', ['acr' => 'anything'], true],
    'essential without values, missing' => ['{"id_token":{"acr":{"essential":true}}}', [], false],
    'single value, lower' => ['{"id_token":{"acr":{"value":"gold"}}}', ['acr' => 'bronze'], false],
    'non-string values only: any acr, present' => ['{"id_token":{"acr":{"values":[42]}}}', ['acr' => 'anything'], true],
    'non-string values only: any acr, missing' => ['{"id_token":{"acr":{"values":[42]}}}', [], false],
    'acr not requested' => ['{"id_token":{"email":null}}', [], true],
    'acr requested as null (voluntary, no constraint)' => ['{"id_token":{"acr":null}}', [], true],
    'not JSON' => ['not-json', [], true],
    'a JSON string' => ['"id_token"', [], true],
    'id_token not an object' => ['{"id_token":"acr"}', [], true],
]);

it('accepts an acr requested through either acr_values or the claims parameter', function (string $returnedAcr): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa.require_requested_acr' => true]);

    $identity = stepUpLogin($identityProvider, ['acr_values' => 'silver', 'claims' => '{"id_token":{"acr":{"values":["gold"]}}}'], ['acr' => $returnedAcr]);

    expect($identity->acr())->toBe($returnedAcr);
})->with(['from acr_values' => 'silver', 'from claims' => 'gold']);

it('reads acr_values separated by several spaces', function (): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa.require_requested_acr' => true]);

    expect(stepUpLogin($identityProvider, ['acr_values' => '  gold   silver '], ['acr' => 'silver'])->acr())->toBe('silver');
});

it('takes only a whole, non-negative max_age from the authorization request', function (string $requestedMaxAge, ?string $sentMaxAge): void {
    FakeIdentityProvider::fake(configOverrides: ['mfa.max_age' => 120]);

    expect(queryParameters(startLogin(browserSession(), ['max_age' => $requestedMaxAge]))['max_age'] ?? null)->toBe($sentMaxAge);
})->with([
    'zero' => ['0', '0'],
    'negative falls back to config' => ['-1', '120'],
    'not a number falls back to config' => ['soon', '120'],
]);

it('requires a login in the very second the IdP sent when max_age is 0', function (): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['id_token.leeway' => 0]);

    expect(fn () => stepUpLogin($identityProvider, ['max_age' => '0'], ['auth_time' => Date::now()->getTimestamp() - 1]))
        ->toThrow(InvalidTokenException::class, 'older than max_age')
        ->and(stepUpLogin($identityProvider, ['max_age' => '0'], ['auth_time' => Date::now()->getTimestamp()])->subject)->toBe('fake-subject-1');
});

it('lets a login without a requested acr through when require_requested_acr is on', function (): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa.require_requested_acr' => true]);

    expect(stepUpLogin($identityProvider)->subject)->toBe('fake-subject-1');
});

it('counts only string amr values, as RFC 8176 defines them', function (): void {
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa.amr_values' => ['1']]);

    expect(isMultiFactorProven(stepUpLogin($identityProvider, claims: ['amr' => [1]])))->toBeFalse()
        ->and(isMultiFactorProven(stepUpLogin($identityProvider, claims: ['amr' => ['1']])))->toBeTrue();
});

it('signs in with an mfa config published before max_age and require_requested_acr existed', function (): void {
    // mergeConfigFrom() only fills top-level keys: an app that published
    // config/oidc.php before S2 has an `mfa` array without the new keys.
    $identityProvider = FakeIdentityProvider::fake(configOverrides: ['mfa' => [
        'required' => false,
        'amr_values' => ['mfa'],
        'acr_values' => ['urn:qiick:loa:mfa'],
        'request_acr_values' => 'urn:qiick:loa:mfa',
    ]]);

    $identity = stepUpLogin($identityProvider, ['acr_values' => 'urn:qiick:loa:mfa'], ['acr' => 'urn:qiick:loa:pwd', 'auth_time' => null]);

    expect($identity->subject)->toBe('fake-subject-1')
        ->and(isMultiFactorProven($identity))->toBeFalse();
});
