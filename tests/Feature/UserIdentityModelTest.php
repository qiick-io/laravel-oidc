<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Config;
use Qiick\Oidc\Models\OidcLogoutRevocation;
use Qiick\Oidc\Models\UserIdentity;
use Qiick\Oidc\Tests\Support\User;
use Qiick\Oidc\Tests\Support\UserWithRoles;

/*
 * The UserIdentity model: what it guards, defaults and casts, and how it
 * finds the app's user model.
 */

it('never mass-assigns the id and starts at format_version 1', function (): void {
    $identity = UserIdentity::query()->create([
        'id' => 999,
        'user_id' => localUser()->id,
        'issuer' => 'https://idp.example.com/realms/test',
        'subject' => 'user-42',
    ]);

    expect($identity->id)->not->toBe(999)
        ->and($identity->format_version)->toBe(1)
        ->and((new UserIdentity)->format_version)->toBe(1);
});

it('casts the login metadata and the format version', function (): void {
    $identity = UserIdentity::query()->create([
        'user_id' => localUser()->id,
        'issuer' => 'https://idp.example.com/realms/test',
        'subject' => 'user-42',
        'last_login_at' => '2026-11-24 12:00:00',
        'last_auth_time_at' => '2026-11-24 11:59:00',
        'last_amr' => ['pwd', 'mfa'],
        'email_verified_at_link' => 1,
        'format_version' => '2',
        'metadata' => ['source' => 'test'],
    ])->fresh();

    expect($identity?->last_login_at)->toBeInstanceOf(CarbonImmutable::class)
        ->and($identity?->last_auth_time_at)->toBeInstanceOf(CarbonImmutable::class)
        ->and($identity?->created_at)->toBeInstanceOf(CarbonImmutable::class)
        ->and($identity?->updated_at)->toBeInstanceOf(CarbonImmutable::class)
        ->and($identity?->last_amr)->toBe(['pwd', 'mfa'])
        ->and($identity?->email_verified_at_link)->toBeTrue()
        ->and($identity?->format_version)->toBe(2)
        ->and($identity?->metadata)->toBe(['source' => 'test'])
        // Drivers that return every column as a string still give an int.
        ->and((new UserIdentity)->setRawAttributes(['format_version' => '3'])->format_version)->toBe(3);
});

it('uses oidc.users.model over the auth provider model', function (): void {
    Config::set(['oidc.users.model' => UserWithRoles::class, 'auth.providers.users.model' => User::class]);

    expect(UserIdentity::userModel())->toBe(UserWithRoles::class);

    Config::set('oidc.users.model', null);

    expect(UserIdentity::userModel())->toBe(User::class);
});

it('refuses a user model that is not an authenticatable Eloquent model', function (mixed $model): void {
    Config::set(['oidc.users.model' => $model, 'auth.providers.users.model' => null]);

    UserIdentity::userModel();
})->throws(LogicException::class, 'oidc.users.model must be an Eloquent model that implements Authenticatable.')->with([
    'missing' => [null],
    'not a class name' => [42],
    'not a model' => [stdClass::class],
    'a model that cannot authenticate' => [UserIdentity::class],
    'an authenticatable that is not a model' => [GenericUser::class],
]);

it('keeps the guarding and attributes an app subclass declares', function (): void {
    $unguardedIdentity = new class extends UserIdentity
    {
        protected $guarded = [];
    };
    $fillableIdentity = new class extends UserIdentity
    {
        protected $fillable = ['subject'];
    };
    $identityWithMetadata = new class extends UserIdentity
    {
        protected $attributes = ['metadata' => '{"source":"app"}'];
    };

    expect($unguardedIdentity->getGuarded())->toBe([])
        ->and($fillableIdentity->getGuarded())->toBe(['*'])
        ->and($fillableIdentity->fill(['subject' => 'user-1', 'issuer' => 'https://idp.example.com'])->getAttributes())
        ->toBe(['format_version' => 1, 'subject' => 'user-1'])
        ->and($identityWithMetadata->metadata)->toBe(['source' => 'app'])
        ->and($identityWithMetadata->format_version)->toBe(1)
        ->and((new OidcLogoutRevocation)->getGuarded())->toBe(['id']);
});
