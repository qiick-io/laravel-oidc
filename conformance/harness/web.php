<?php

declare(strict_types=1);

/*
 * routes/web.php of the conformance harness app (a fresh `laravel/laravel` with this
 * package required from a path repository). Plain-text pages so rp-driver.py can tell
 * a signed-in user from a refused login. Never ship these routes in an application.
 */

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Services\JwksService;
use Qiick\Oidc\Services\RpInitiatedLogoutService;

Route::middleware('web')->group(function (): void {
    Route::get('/', fn () => Auth::check()
        ? response('RP-LOGGED-IN '.Auth::user()->email)
        : redirect('/login'));

    Route::get('/login', fn (Request $request) => response(
        'RP-LOGIN-PAGE '.implode(' | ', $request->session()->get('errors')?->all() ?? []),
    ))->name('login');

    // Each suite module publishes fresh keys; forget the cached discovery and JWKS.
    Route::get('/harness/reset', function () {
        Cache::flush();

        return response('RESET');
    });

    // The Config RP discovery modules end once discovery and the JWKS are fetched.
    // key() throws on the suite's multi-key JWKS after fetching it, which is all the module needs.
    Route::get('/harness/discover', function () {
        $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
        $discovery = app(DiscoveryService::class)->discover($configuration);
        app(JwksService::class)->key($discovery, null, 'RS256');

        return response('RP-DISCOVERED');
    });

    Route::get('/logout', function (Request $request, RpInitiatedLogoutService $rpInitiatedLogout) {
        $endSessionUrl = $rpInitiatedLogout->endSessionUrl($request->session());
        Auth::logout();
        $request->session()->invalidate();

        return $endSessionUrl !== null ? redirect()->away($endSessionUrl) : response('RP-LOGGED-OUT-LOCAL');
    });
});
