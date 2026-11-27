<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Http\Controllers\BackChannelLogoutController;
use Qiick\Oidc\Http\Controllers\FrontChannelLogoutController;
use Qiick\Oidc\Http\Controllers\OidcCallbackController;
use Qiick\Oidc\Http\Controllers\OidcRedirectController;
use Qiick\Oidc\Http\Controllers\PostLogoutReturnController;

/*
 * Routes registered by the package under `oidc.routes.prefix`.
 *
 * Redirect and callback are browser routes with `oidc.routes.middleware`
 * (web + guest by default). Back-channel and front-channel logout are called
 * without a browser session: no CSRF, no cookies.
 *
 * `oidc.routes.except` lists route names the app registers itself (S4), so a
 * product can own e.g. oidc.callback and still receive every other package route.
 */
$browserMiddleware = config('oidc.routes.middleware', ['web', 'guest']);
$exceptedRouteNames = config('oidc.routes.except', []);
$exceptedRouteNames = is_array($exceptedRouteNames) ? $exceptedRouteNames : [];

$shouldRegister = static fn (string $routeName): bool => ! in_array($routeName, $exceptedRouteNames, true);

Route::middleware(is_array($browserMiddleware) ? $browserMiddleware : ['web'])->group(function () use ($shouldRegister): void {
    if ($shouldRegister('oidc.redirect')) {
        Route::get('redirect', OidcRedirectController::class)->name('oidc.redirect');
    }

    if ($shouldRegister('oidc.callback')) {
        Route::get('callback', OidcCallbackController::class)->name('oidc.callback');
    }
});

if ($shouldRegister('oidc.backchannel-logout')) {
    Route::post('backchannel-logout', BackChannelLogoutController::class)
        // An IdP's server traffic has a budget independent of browser requests.
        ->middleware('throttle:60,1,oidc-backchannel-logout:')
        ->name('oidc.backchannel-logout');
}

if ($shouldRegister('oidc.logged-out')) {
    // Throttled like front-channel logout: every unmatched state logs a warning.
    Route::middleware(['web', 'throttle:60,1'])->get('logged-out', PostLogoutReturnController::class)->name('oidc.logged-out');
}

if ($shouldRegister('oidc.frontchannel-logout')) {
    Route::get('frontchannel-logout', FrontChannelLogoutController::class)
        ->middleware('throttle:60,1')
        ->name('oidc.frontchannel-logout');
}
