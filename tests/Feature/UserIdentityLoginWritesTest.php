<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Schema;
use Qiick\Oidc\Contracts\UserClaimSynchronizationContract;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Models\UserIdentity;

/*
 * M2: every login writes last_* auth metadata from the validated id_token.
 * S9: UserClaimSynchronizationContract runs after role mapping (no-op by default).
 */

it('writes last login auth metadata from the validated id_token on every login', function (): void {
    Date::setTestNow('2026-11-22 12:00:00');
    $user = localUser();
    linkIdentity($user, 'user-42');
    $authenticationTime = Date::now()->subMinute()->getTimestamp();

    ssoLogin($this, fakeProvider(), [
        'sub' => 'user-42',
        'auth_time' => $authenticationTime,
        'acr' => 'urn:mace:incommon:iap:silver',
        'amr' => ['pwd', 'mfa'],
    ])->assertRedirect('/');

    $identity = UserIdentity::query()->sole();

    expect($identity->last_login_at?->equalTo(Date::now()))->toBeTrue()
        ->and($identity->last_auth_time_at?->getTimestamp())->toBe($authenticationTime)
        ->and($identity->last_acr)->toBe('urn:mace:incommon:iap:silver')
        ->and($identity->last_amr)->toBe(['pwd', 'mfa'])
        ->and($identity->last_id_token_alg)->toBe('RS256');
});

it('snapshots link-time profile claims and link_method on auto-link', function (): void {
    $user = localUser('ada@example.com');

    ssoLogin($this, fakeProvider(['auto_link' => true]), [
        'sub' => 'user-42',
        'email' => 'ada@example.com',
        'email_verified' => true,
        'preferred_username' => 'ada',
        'name' => 'Ada Lovelace',
    ])->assertRedirect('/');

    expect(UserIdentity::query()->sole()->only([
        'link_method',
        'email_at_link',
        'email_verified_at_link',
        'preferred_username_at_link',
        'name_at_link',
    ]))->toBe([
        'link_method' => 'auto_link_email',
        'email_at_link' => 'ada@example.com',
        'email_verified_at_link' => true,
        'preferred_username_at_link' => 'ada',
        'name_at_link' => 'Ada Lovelace',
    ]);
});

it('sets link_method to jit when provisioning a new user', function (): void {
    ssoLogin($this, fakeProvider(['jit' => true]), [
        'sub' => 'new-user',
        'email' => 'new@example.com',
        'email_verified' => true,
    ])->assertRedirect('/');

    expect(UserIdentity::query()->sole()->link_method)->toBe('jit');
});

it('calls the claim synchronisation contract after a successful login', function (): void {
    $user = localUser();
    linkIdentity($user, 'user-42');
    $synchronizedUserIds = new class
    {
        /** @var list<int> */
        public array $ids = [];
    };

    app()->instance(UserClaimSynchronizationContract::class, new class($synchronizedUserIds) implements UserClaimSynchronizationContract
    {
        public function __construct(private object $synchronizedUserIds) {}

        public function synchronize(Model&Authenticatable $user, AuthenticatedIdentityData $identity): void
        {
            $this->synchronizedUserIds->ids[] = (int) $user->getAuthIdentifier();
        }
    });

    ssoLogin($this, fakeProvider(), ['sub' => 'user-42'])->assertRedirect('/');

    expect($synchronizedUserIds->ids)->toBe([(int) $user->id]);
});

it('leaves local user columns untouched under the default no-op claim synchroniser', function (): void {
    $user = localUser('ada@example.com', ['name' => 'Admin Edited Name']);
    linkIdentity($user, 'user-42');

    ssoLogin($this, fakeProvider(), [
        'sub' => 'user-42',
        'name' => 'IdP Profile Name',
        'email' => 'idp-profile@example.com',
    ])->assertRedirect('/');

    expect($user->fresh()->only(['name', 'email']))->toBe([
        'name' => 'Admin Edited Name',
        'email' => 'ada@example.com',
    ]);
});

it('marks legacy imports with link_method legacy_import', function (): void {
    Schema::table('users', fn (Blueprint $table) => $table->string('oidc_sub')->nullable()->unique());
    Config::set('oidc.issuer', 'https://idp.example.com/realms/externa');
    $user = localUser('ada@example.com', ['oidc_sub' => 'sub-ada']);

    $this->artisan('oidc:import-legacy-subjects')->assertSuccessful();

    expect(UserIdentity::query()->where('user_id', $user->id)->sole()->link_method)->toBe('legacy_import');
});
