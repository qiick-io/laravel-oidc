<?php

declare(strict_types=1);

use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Testing\TestResponse;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Data\IdentitySessionData;
use Qiick\Oidc\Enums\LoginRefusalReasonEnum;
use Qiick\Oidc\Models\UserIdentity;
use Qiick\Oidc\Services\AuthorizationCodeFlowService;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Testing\FakeIdentityProvider;
use Qiick\Oidc\Tests\Support\PackageTestCase;
use Qiick\Oidc\Tests\Support\User;

pest()->extend(PackageTestCase::class)->in('Feature', 'Unit', 'Integration');

/**
 * A request on the app with the given session, as the browser would send it.
 */
function browserRequest(string $url, Session $session): Request
{
    $request = Request::create($url);
    $request->setLaravelSession($session);

    return $request;
}

/**
 * A fresh session per call, like a separate browser.
 */
function browserSession(): Session
{
    $session = new Store('laravel_session', new ArraySessionHandler(10));
    $session->start();

    return $session;
}

/**
 * Starts a login and returns the authorization URL the browser is sent to.
 *
 * @param  array<string, string>  $additionalParameters
 */
function startLogin(Session $session, array $additionalParameters = []): string
{
    return (string) app(AuthorizationCodeFlowService::class)
        ->redirect(browserRequest('http://localhost/auth/oidc/redirect', $session), $additionalParameters)
        ->getTargetUrl();
}

/**
 * Runs the whole flow against the fake IdP and returns the identity.
 *
 * @param  array<string, mixed>  $claims  id_token claim overrides
 */
function completeLogin(FakeIdentityProvider $identityProvider, array $claims = []): AuthenticatedIdentityData
{
    $session = browserSession();
    $callbackUrl = $identityProvider->authorize(startLogin($session), $claims);

    return app(AuthorizationCodeFlowService::class)->handleCallback(browserRequest($callbackUrl, $session));
}

/**
 * @return array<string, string>
 */
function queryParameters(string $url): array
{
    parse_str((string) parse_url($url, PHP_URL_QUERY), $parameters);

    /** @var array<string, string> $parameters */
    return $parameters;
}

/**
 * Clicks the SSO button, logs in at the fake IdP and follows the callback.
 *
 * @param  array<string, mixed>  $claims
 */
function ssoLogin(PackageTestCase $testCase, FakeIdentityProvider $identityProvider, array $claims = []): TestResponse
{
    $authorizationUrl = (string) $testCase->get('/auth/oidc/redirect')->assertRedirect()->headers->get('Location');

    return $testCase->get($identityProvider->authorize($authorizationUrl, $claims));
}

function localUser(string $email = 'ada@example.com', array $attributes = []): User
{
    return User::query()->forceCreate(['name' => 'Ada', 'email' => $email, 'password' => 'not-used', ...$attributes]);
}

function linkIdentity(User $user, string $subject = 'fake-subject-1', string $issuer = 'https://idp.example.com/realms/test'): UserIdentity
{
    return UserIdentity::query()->create(['user_id' => $user->id, 'issuer' => $issuer, 'subject' => $subject]);
}

/**
 * @param  array<string, mixed>  $configOverrides
 */
function fakeProvider(array $configOverrides = []): FakeIdentityProvider
{
    return FakeIdentityProvider::fake(configOverrides: $configOverrides);
}

function assertRefused(TestResponse $response, LoginRefusalReasonEnum $reason): void
{
    $response->assertRedirect('/login')->assertSessionHasErrors(['email' => $reason->message()]);
    expect(auth()->check())->toBeFalse();
}

/**
 * Session data holding $identity as IdentitySessionService stores it, for
 * tests that start from an SSO session without going through the login.
 *
 * @return array<string, mixed>
 */
function storedSsoSession(IdentitySessionData $identity): array
{
    return [IdentitySessionService::SESSION_KEY => $identity->toArray()];
}
