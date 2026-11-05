<?php

declare(strict_types=1);

use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Services\AuthorizationCodeFlowService;
use Qiick\Oidc\Testing\FakeIdentityProvider;
use Qiick\Oidc\Tests\Support\PackageTestCase;

pest()->extend(PackageTestCase::class)->in('Feature', 'Unit');

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
