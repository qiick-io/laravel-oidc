<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Http\Controllers\BackChannelLogoutController;

/*
 * Routes registered by the package under `oidc.routes.prefix`. The
 * back-channel logout endpoint is called server to server by the IdP: no
 * session, no CSRF token, no cookies. Register its absolute URL at the IdP.
 */
Route::post('backchannel-logout', BackChannelLogoutController::class)
    ->name('oidc.backchannel-logout');
