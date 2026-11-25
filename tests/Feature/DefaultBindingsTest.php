<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Database\Eloquent\Casts\AsStringable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Stringable;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Data\DiscoveryDocumentData;
use Qiick\Oidc\Services\EloquentUserProvisioningService;
use Qiick\Oidc\Services\RoleBreakGlassPolicyService;
use Qiick\Oidc\Tests\Support\User;
use Qiick\Oidc\Tests\Support\UserWithRoles;

/*
 * The package's default implementations of the provisioning and break-glass
 * contracts, and the discovery value object's defaults.
 */

/**
 * @param  array<string, mixed>  $claims
 */
function identityWithClaims(array $claims): AuthenticatedIdentityData
{
    return new AuthenticatedIdentityData('https://idp.example.com', 'user-42', $claims, 'header.payload.signature', 'access-token', null);
}

it('provisions a verified user with an unusable password and the best name available', function (array $claims, string $name): void {
    Date::setTestNow('2026-11-24 12:00:00');

    $user = (new EloquentUserProvisioningService)->provision(identityWithClaims($claims), 'ada.lovelace@example.com');

    expect($user->getAttribute('name'))->toBe($name)
        ->and($user->getAttribute('email'))->toBe('ada.lovelace@example.com')
        ->and(Date::parse($user->getAttribute('email_verified_at'))->equalTo(Date::now()))->toBeTrue()
        ->and(Hash::check('', (string) $user->getAttribute('password')))->toBeFalse()
        ->and(User::query()->count())->toBe(1);
})->with([
    'name claim, trimmed' => [['name' => '  Ada Lovelace '], 'Ada Lovelace'],
    'blank name, given and family name' => [['name' => '  ', 'given_name' => 'Ada', 'family_name' => 'Lovelace'], 'Ada Lovelace'],
    'no name claims' => [[], 'ada.lovelace'],
]);

it('gives every provisioned user a different unusable password', function (): void {
    $first = (new EloquentUserProvisioningService)->provision(identityWithClaims([]), 'first@example.com');
    $second = (new EloquentUserProvisioningService)->provision(identityWithClaims([]), 'second@example.com');

    expect($first->getAttribute('password'))->not->toBe($second->getAttribute('password'));
});

it('recognises a break-glass account by role and confirmed second factor', function (array $attributes, array $roles, bool $isTwoFactorRequired, bool $isBreakGlass): void {
    Schema::table('users', function (Blueprint $table): void {
        $table->text('two_factor_secret')->nullable();
        $table->timestamp('two_factor_confirmed_at')->nullable();
    });
    UserWithRoles::$rolesByEmail = [];
    $user = UserWithRoles::query()->forceCreate(['name' => 'Owner', 'email' => 'owner@example.com', 'password' => 'x', ...$attributes])->fresh();
    $user->roleNames = $roles;

    expect((new RoleBreakGlassPolicyService(['super-admin', 'owner'], $isTwoFactorRequired))->isBreakGlassAccount($user))->toBe($isBreakGlass);
})->with([
    'role and confirmed 2FA' => [['two_factor_secret' => 's', 'two_factor_confirmed_at' => '2026-11-24 12:00:00'], ['owner'], true, true],
    'second listed role' => [['two_factor_secret' => 's', 'two_factor_confirmed_at' => '2026-11-24 12:00:00'], ['super-admin'], true, true],
    'role, 2FA not confirmed' => [['two_factor_secret' => 's'], ['owner'], true, false],
    'role, no secret' => [['two_factor_confirmed_at' => '2026-11-24 12:00:00'], ['owner'], true, false],
    'role, empty secret' => [['two_factor_secret' => '', 'two_factor_confirmed_at' => '2026-11-24 12:00:00'], ['owner'], true, false],
    'role, 2FA not required' => [[], ['owner'], false, true],
    'no break-glass role' => [['two_factor_secret' => 's', 'two_factor_confirmed_at' => '2026-11-24 12:00:00'], ['admin'], true, false],
]);

it('treats a secret without a confirmation column as confirmed', function (): void {
    Schema::table('users', fn (Blueprint $table) => $table->text('two_factor_secret')->nullable());
    $user = UserWithRoles::query()->forceCreate(['name' => 'Owner', 'email' => 'owner@example.com', 'password' => 'x', 'two_factor_secret' => 's'])->fresh();
    $user->roleNames = ['owner'];

    expect((new RoleBreakGlassPolicyService(['owner'], true))->isBreakGlassAccount($user))->toBeTrue();
});

it('counts a secret the app casts to an object as a second factor, unless it renders empty', function (string $storedSecret, bool $isBreakGlass): void {
    Schema::table('users', fn (Blueprint $table) => $table->text('two_factor_secret')->nullable());
    $user = UserWithRoles::query()->forceCreate(['name' => 'Owner', 'email' => 'owner@example.com', 'password' => 'x', 'two_factor_secret' => $storedSecret])->fresh()
        ?->mergeCasts(['two_factor_secret' => AsStringable::class]);
    $user->roleNames = ['owner'];

    expect($user->getAttribute('two_factor_secret'))->toBeInstanceOf(Stringable::class)
        ->and((new RoleBreakGlassPolicyService(['owner'], true))->isBreakGlassAccount($user))->toBe($isBreakGlass);
})->with(['a secret' => ['s', true], 'an empty secret' => ['', false], 'a whitespace secret' => ['   ', false]]);

it('never treats a user without Eloquent or role methods as break-glass', function (object $user): void {
    expect((new RoleBreakGlassPolicyService(['owner'], false))->isBreakGlassAccount($user))->toBeFalse();
})->with([
    'not an Eloquent model' => fn () => new GenericUser(['id' => 1]),
    'not an Eloquent model, with roles' => fn () => new class(['id' => 1]) extends GenericUser
    {
        public function hasRole(string $role): bool
        {
            return true;
        }
    },
    'a model without roles' => fn () => new User,
]);

it('defaults every discovery capability to its spec default and round-trips through the cache', function (): void {
    $bare = new DiscoveryDocumentData('https://idp.example.com', 'https://idp.example.com/auth', 'https://idp.example.com/token', 'https://idp.example.com/jwks', null, null, ['RS256'], false);
    $full = new DiscoveryDocumentData('https://idp.example.com', 'https://idp.example.com/auth', 'https://idp.example.com/token', 'https://idp.example.com/jwks', 'https://idp.example.com/userinfo', 'https://idp.example.com/logout', ['RS256', 'ES256'], true, true, true, true, true, ['gold'], true);

    expect([$bare->isFrontChannelLogoutSupported, $bare->isFrontChannelLogoutSessionSupported, $bare->isBackChannelLogoutSupported, $bare->isBackChannelLogoutSessionSupported, $bare->acrValuesSupported, $bare->isClaimsParameterSupported])
        ->toBe([false, false, false, false, null, false])
        ->and(DiscoveryDocumentData::fromArray($full->toArray()))->toEqual($full)
        ->and(DiscoveryDocumentData::fromArray($bare->toArray()))->toEqual($bare);
});
