<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use Qiick\Oidc\Models\UserIdentity;

beforeEach(function (): void {
    Schema::table('users', fn (Blueprint $table) => $table->string('oidc_sub')->nullable()->unique());
    Config::set('oidc.issuer', 'https://idp.example.com/realms/externa');
});

it('imports legacy subjects with the configured issuer and is idempotent', function (): void {
    $linkedUser = localUser('ada@example.com', ['oidc_sub' => 'sub-ada']);
    localUser('local@example.com');
    localUser('empty@example.com', ['oidc_sub' => '']);

    $this->artisan('oidc:import-legacy-subjects')
        ->expectsOutputToContain('Imported 1 identity for issuer https://idp.example.com/realms/externa; 0 already linked, 0 conflicts.')
        ->assertSuccessful();

    expect(UserIdentity::query()->sole()->only(['user_id', 'issuer', 'subject']))
        ->toBe(['user_id' => $linkedUser->id, 'issuer' => 'https://idp.example.com/realms/externa', 'subject' => 'sub-ada']);

    $this->artisan('oidc:import-legacy-subjects')
        ->expectsOutputToContain('Imported 0 identities for issuer https://idp.example.com/realms/externa; 1 already linked, 0 conflicts.')
        ->assertSuccessful();
});

it('lets the imported identity sign in through SSO', function (): void {
    $user = localUser('ada@example.com', ['oidc_sub' => 'sub-ada']);
    $identityProvider = fakeProvider();
    $this->artisan('oidc:import-legacy-subjects', ['--issuer' => $identityProvider->issuer])->assertSuccessful();

    ssoLogin($this, $identityProvider, ['sub' => 'sub-ada'])->assertRedirect('/');

    expect(auth()->id())->toBe($user->id);
});

it('reports a subject already linked to another user and never moves it', function (): void {
    $owner = localUser('owner@example.com');
    linkIdentity($owner, 'sub-shared', 'https://idp.example.com/realms/externa');
    localUser('other@example.com', ['oidc_sub' => 'sub-shared']);

    $this->artisan('oidc:import-legacy-subjects')
        ->expectsOutputToContain('already linked to user '.$owner->id)
        ->assertFailed();

    expect(UserIdentity::query()->sole()->user_id)->toBe($owner->id);
});

it('reports a user already linked to another subject of the issuer', function (bool $isDryRun): void {
    $user = localUser('ada@example.com', ['oidc_sub' => 'sub-legacy']);
    linkIdentity($user, 'sub-auto-linked', 'https://idp.example.com/realms/externa');

    $this->artisan('oidc:import-legacy-subjects', ['--dry-run' => $isDryRun])
        ->expectsOutputToContain('User '.$user->id.': already linked to another subject of this issuer; skipped.')
        ->expectsOutputToContain('0 already linked, 1 conflicts')
        ->assertFailed();

    expect(UserIdentity::query()->sole()->subject)->toBe('sub-auto-linked');
})->with(['import' => false, 'dry run' => true]);

it('falls back to the default column and the configured issuer for empty options', function (): void {
    $user = localUser('ada@example.com', ['oidc_sub' => 'sub-ada']);

    $this->artisan('oidc:import-legacy-subjects', ['--column' => '', '--issuer' => ''])
        ->expectsOutputToContain('Imported 1 identity for issuer https://idp.example.com/realms/externa')
        ->assertSuccessful();

    expect(UserIdentity::query()->sole()->user_id)->toBe($user->id);
});

it('fails with an empty configured issuer', function (): void {
    Config::set('oidc.issuer', '');

    $this->artisan('oidc:import-legacy-subjects')->expectsOutputToContain('No issuer')->assertFailed();
});

it('writes nothing on a dry run', function (): void {
    localUser('ada@example.com', ['oidc_sub' => 'sub-ada']);

    $this->artisan('oidc:import-legacy-subjects', ['--dry-run' => true])
        ->expectsOutputToContain('Would import 1 identity')
        ->assertSuccessful();

    expect(UserIdentity::query()->count())->toBe(0);
});

it('fails without an issuer or without the column', function (): void {
    Config::set('oidc.issuer', null);
    $this->artisan('oidc:import-legacy-subjects')->expectsOutputToContain('No issuer')->assertFailed();

    $this->artisan('oidc:import-legacy-subjects', ['--issuer' => 'https://idp.example.com', '--column' => 'missing'])
        ->expectsOutputToContain('has no [missing] column')
        ->assertFailed();
});
