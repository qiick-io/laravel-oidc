<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;
use Qiick\Oidc\Services\SsoOnlyModeService;
use Qiick\Oidc\Tests\Support\UserWithRoles;

/**
 * @param  list<string>  $roles
 */
function userWithRoles(string $email, array $roles = [], bool $hasConfirmedSecondFactor = false): UserWithRoles
{
    UserWithRoles::$rolesByEmail[$email] = $roles;

    return UserWithRoles::query()->forceCreate([
        'name' => 'User',
        'email' => $email,
        'password' => Hash::make('correct-password'),
        'two_factor_secret' => $hasConfirmedSecondFactor ? 'encrypted-secret' : null,
        'two_factor_confirmed_at' => $hasConfirmedSecondFactor ? Date::now() : null,
    ]);
}

function ssoOnly(): SsoOnlyModeService
{
    return app(SsoOnlyModeService::class);
}

beforeEach(function (): void {
    Schema::table('users', function (Blueprint $table): void {
        $table->text('two_factor_secret')->nullable();
        $table->timestamp('two_factor_confirmed_at')->nullable();
    });
    Config::set('auth.providers.users.model', UserWithRoles::class);
    UserWithRoles::$rolesByEmail = [];
    fakeProvider(['only' => true]);
});

it('is active only while SSO itself is configured, so turning SSO off never locks anyone out', function (): void {
    expect(ssoOnly()->isActive())->toBeTrue();

    Config::set('oidc.enabled', false);
    expect(ssoOnly()->isActive())->toBeFalse()
        ->and(ssoOnly()->canUseLocalLogin(userWithRoles('ada@example.com')))->toBeTrue();

    Config::set('oidc.enabled', true);
    Config::set('oidc.only', false);
    expect(ssoOnly()->isActive())->toBeFalse();
});

it('keeps local login only for break-glass accounts', function (array $roles, bool $hasConfirmedSecondFactor, bool $canUseLocalLogin): void {
    expect(ssoOnly()->canUseLocalLogin(userWithRoles('user@example.com', $roles, $hasConfirmedSecondFactor)))->toBe($canUseLocalLogin);
})->with([
    'regular user' => [['admin'], true, false],
    'super-admin with confirmed 2FA' => [['super-admin'], true, true],
    'super-admin without 2FA' => [['super-admin'], false, false],
]);

it('accepts a break-glass account without 2FA only when configured', function (): void {
    Config::set('oidc.break_glass.require_two_factor', false);

    expect(ssoOnly()->canUseLocalLogin(userWithRoles('owner@example.com', ['super-admin'])))->toBeTrue();
});

it('accepts other break-glass roles when configured', function (): void {
    Config::set('oidc.break_glass.roles', ['owner']);

    expect(ssoOnly()->canUseLocalLogin(userWithRoles('owner@example.com', ['owner'], true)))->toBeTrue()
        ->and(ssoOnly()->canUseLocalLogin(userWithRoles('root@example.com', ['super-admin'], true)))->toBeFalse();
});

it('refuses password logins through Auth::attempt() for everyone but break-glass accounts', function (): void {
    userWithRoles('ada@example.com', ['admin'], true);
    userWithRoles('owner@example.com', ['super-admin'], true);

    expect(fn () => Auth::attempt(['email' => 'ada@example.com', 'password' => 'correct-password']))
        ->toThrow(ValidationException::class, 'Password sign-in is disabled. Use single sign-on.')
        ->and(Auth::check())->toBeFalse()
        ->and(Auth::attempt(['email' => 'owner@example.com', 'password' => 'correct-password']))->toBeTrue();
});

it('does not touch password logins outside SSO-only mode or with a wrong password', function (): void {
    userWithRoles('ada@example.com');

    expect(Auth::attempt(['email' => 'ada@example.com', 'password' => 'wrong-password']))->toBeFalse();

    Config::set('oidc.only', false);
    expect(Auth::attempt(['email' => 'ada@example.com', 'password' => 'correct-password']))->toBeTrue();
});

it('gives the login page what it needs', function (): void {
    expect(ssoOnly()->loginOptions(Request::create('/login'))->toArray())->toBe([
        'isSsoAvailable' => true,
        'isSsoOnly' => true,
        'isPasswordLoginVisible' => false,
        'buttonLabel' => 'Sign in with SSO',
        'redirectUrl' => 'http://localhost/auth/oidc/redirect',
    ])
        ->and(ssoOnly()->loginOptions(Request::create('/login?local=1'))->isPasswordLoginVisible)->toBeTrue();

    Config::set('oidc.button_label', 'Company SSO');
    Config::set('oidc.only', false);
    expect(ssoOnly()->loginOptions(Request::create('/login'))->toArray())->toMatchArray([
        'isSsoOnly' => false,
        'isPasswordLoginVisible' => true,
        'buttonLabel' => 'Company SSO',
    ]);

    Config::set('oidc.enabled', false);
    expect(ssoOnly()->loginOptions(Request::create('/login'))->toArray())->toMatchArray([
        'isSsoAvailable' => false,
        'redirectUrl' => null,
    ]);
});
