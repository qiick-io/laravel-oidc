<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Http\Controllers\BackChannelLogoutController;
use Qiick\Oidc\Http\Controllers\OidcCallbackController;
use Qiick\Oidc\Http\Controllers\OidcRedirectController;

/*
 * Routes registered by the package under `oidc.routes.prefix`.
 *
 * Redirect and callback are browser routes with `oidc.routes.middleware`
 * (web + guest by default). The back-channel logout endpoint is called server
 * to server by the IdP: no session, no CSRF token, no cookies.
 */
$browserMiddleware = config('oidc.routes.middleware', ['web', 'guest']);

Route::middleware(is_array($browserMiddleware) ? $browserMiddleware : ['web'])->group(function (): void {
    Route::get('redirect', OidcRedirectController::class)->name('oidc.redirect');
    Route::get('callback', OidcCallbackController::class)->name('oidc.callback');
});

Route::post('backchannel-logout', BackChannelLogoutController::class)
    ->name('oidc.backchannel-logout');
