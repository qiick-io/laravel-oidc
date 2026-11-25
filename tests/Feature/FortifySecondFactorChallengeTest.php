<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Casts\AsStringable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Stringable;
use Qiick\Oidc\Services\FortifySecondFactorChallengeService;
use Qiick\Oidc\Tests\Support\Fortify\FakeFortify;
use Qiick\Oidc\Tests\Support\Fortify\FakeTwoFactorAuthenticatable;
use Qiick\Oidc\Tests\Support\Fortify\UserWithTwoFactor;
use Qiick\Oidc\Tests\Support\User;

/*
 * The default second factor starts Fortify's two-factor challenge exactly as
 * Fortify's own login pipeline does, and only for a user who has a usable
 * second factor. Fortify itself is replaced by test doubles.
 */

beforeEach(function (): void {
    Schema::table('users', function (Blueprint $table): void {
        $table->text('two_factor_secret')->nullable();
        $table->timestamp('two_factor_confirmed_at')->nullable();
    });
    Route::get('/two-factor-challenge', fn () => 'challenge')->name('two-factor.login');
    Route::getRoutes()->refreshNameLookups();
    FakeFortify::$isConfirmationRequired = true;
});

function fortifyChallengeService(): FortifySecondFactorChallengeService
{
    return new FortifySecondFactorChallengeService(
        isRequiredByDefault: true,
        fortifyClass: FakeFortify::class,
        twoFactorTrait: FakeTwoFactorAuthenticatable::class,
    );
}

/**
 * @param  array<string, mixed>  $attributes
 */
function userWithTwoFactor(array $attributes): UserWithTwoFactor
{
    return UserWithTwoFactor::query()->forceCreate(['name' => 'Ada', 'email' => 'ada@example.com', 'password' => 'not-used', ...$attributes]);
}

it('starts the challenge for a user with a confirmed second factor', function (bool $shouldRemember): void {
    $user = userWithTwoFactor(['two_factor_secret' => 'secret', 'two_factor_confirmed_at' => Date::now()]);
    $request = browserRequest('http://localhost/auth/oidc/callback', browserSession());

    $response = fortifyChallengeService()->challenge($request, $user, $shouldRemember);

    expect($response?->getTargetUrl())->toBe('http://localhost/two-factor-challenge')
        ->and($request->session()->get('login.id'))->toBe($user->getKey())
        ->and($request->session()->get('login.remember'))->toBe($shouldRemember);
})->with(['remember' => true, 'no remember' => false]);

it('challenges a secret the app casts to an object, failing closed', function (): void {
    // An app may cast the secret (encrypted, AsStringable, a value object):
    // anything but null or an empty string counts as a second factor.
    $user = userWithTwoFactor(['two_factor_secret' => 'secret', 'two_factor_confirmed_at' => Date::now()])
        ->mergeCasts(['two_factor_secret' => AsStringable::class]);

    expect($user->getAttribute('two_factor_secret'))->toBeInstanceOf(Stringable::class)
        ->and(fortifyChallengeService()->challenge(browserRequest('http://localhost/auth/oidc/callback', browserSession()), $user, false))->not->toBeNull();
});

it('reads a cast secret that renders empty as no second factor, and any other cast value as one', function (string $storedSecret, string $cast, bool $isChallenged): void {
    $user = userWithTwoFactor(['two_factor_secret' => $storedSecret, 'two_factor_confirmed_at' => Date::now()])
        ->mergeCasts(['two_factor_secret' => $cast]);

    $response = fortifyChallengeService()->challenge(browserRequest('http://localhost/auth/oidc/callback', browserSession()), $user, false);

    expect($response !== null)->toBe($isChallenged);
})->with([
    'empty Stringable' => ['', AsStringable::class, false],
    'whitespace Stringable' => ['   ', AsStringable::class, false],
    'empty array' => ['[]', 'array', false],
    'array value' => ['["secret"]', 'array', true],
]);

it('challenges an unconfirmed secret only when Fortify does not require confirmation', function (bool $isConfirmationRequired, bool $isChallenged): void {
    FakeFortify::$isConfirmationRequired = $isConfirmationRequired;
    $user = userWithTwoFactor(['two_factor_secret' => 'secret']);

    $response = fortifyChallengeService()->challenge(browserRequest('http://localhost/auth/oidc/callback', browserSession()), $user, false);

    expect($response !== null)->toBe($isChallenged);
})->with([
    'confirmation required' => [true, false],
    'confirmation not required' => [false, true],
]);

it('has nothing to challenge without a usable second factor', function (Closure $makeUser, ?string $fortifyClass): void {
    $service = new FortifySecondFactorChallengeService(true, $fortifyClass ?? FakeFortify::class, FakeTwoFactorAuthenticatable::class);
    $request = browserRequest('http://localhost/auth/oidc/callback', browserSession());

    expect($service->challenge($request, $makeUser(), false))->toBeNull()
        ->and($request->session()->has('login.id'))->toBeFalse();
})->with([
    'no secret' => [fn () => userWithTwoFactor(['two_factor_confirmed_at' => Date::now()]), null],
    'empty secret' => [fn () => userWithTwoFactor(['two_factor_secret' => '', 'two_factor_confirmed_at' => Date::now()]), null],
    'model without the two-factor trait' => [fn () => User::query()->forceCreate(['name' => 'Ada', 'email' => 'ada@example.com', 'password' => 'x']), null],
    'Fortify not installed' => [fn () => userWithTwoFactor(['two_factor_secret' => 'secret', 'two_factor_confirmed_at' => Date::now()]), 'Laravel\Fortify\Missing'],
]);

it('has nothing to challenge when the app has no two-factor challenge route', function (): void {
    app('router')->setRoutes(new RouteCollection);
    $user = userWithTwoFactor(['two_factor_secret' => 'secret', 'two_factor_confirmed_at' => Date::now()]);

    expect(fortifyChallengeService()->challenge(browserRequest('http://localhost/auth/oidc/callback', browserSession()), $user, false))->toBeNull();
});

it('requires the second factor as configured', function (bool $isRequired): void {
    expect((new FortifySecondFactorChallengeService($isRequired))->isRequired(userWithTwoFactor([])))->toBe($isRequired);
})->with(['required' => true, 'not required' => false]);
