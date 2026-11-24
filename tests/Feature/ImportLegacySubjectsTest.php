<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
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
    expect(UserIdentity::query()->sole()->created_at)->not->toBeNull()
        ->and(UserIdentity::query()->sole()->updated_at)->not->toBeNull()
        ->and(UserIdentity::query()->sole()->public_id)->toBeString();

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

it('counts a link made by a concurrent login while importing', function (string $concurrentSubject, string $expectedOutput): void {
    $user = localUser('ada@example.com', ['oidc_sub' => 'sub-ada']);
    $hasRun = false;

    // A login links the user between the importer's checks and its insert.
    DB::listen(function (QueryExecuted $query) use ($user, $concurrentSubject, &$hasRun): void {
        if ($hasRun || ! str_starts_with($query->sql, 'select exists') || ! str_contains($query->sql, 'user_identities')) {
            return;
        }

        $hasRun = true;
        DB::table('user_identities')->insert([
            'public_id' => (string) Str::uuid7(),
            'user_id' => $user->id,
            'issuer' => 'https://idp.example.com/realms/externa',
            'subject' => $concurrentSubject,
        ]);
    });

    $this->artisan('oidc:import-legacy-subjects')->expectsOutputToContain($expectedOutput);

    expect(UserIdentity::query()->sole()->subject)->toBe($concurrentSubject);
})->with([
    'same subject' => ['sub-ada', '0 identities for issuer https://idp.example.com/realms/externa; 1 already linked, 0 conflicts.'],
    'another subject' => ['sub-other', 'linked concurrently to another identity of this issuer; skipped.'],
    'another subject, counted' => ['sub-other', '0 identities for issuer https://idp.example.com/realms/externa; 0 already linked, 1 conflicts.'],
]);

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

it('reports a legacy subject longer than 255 characters instead of truncating it', function (): void {
    Schema::table('users', fn (Blueprint $table) => $table->string('long_oidc_sub', 300)->nullable());
    $user = localUser('ada@example.com', ['long_oidc_sub' => str_repeat('s', 256)]);
    $fittingUser = localUser('grace@example.com', ['long_oidc_sub' => str_repeat('g', 255)]);

    $this->artisan('oidc:import-legacy-subjects', ['--column' => 'long_oidc_sub'])
        ->expectsOutputToContain("User {$user->id}: the legacy subject is longer than 255 characters; skipped.")
        ->expectsOutputToContain('Imported 1 identity for issuer https://idp.example.com/realms/externa; 0 already linked, 1 conflicts.')
        ->assertFailed();

    expect(UserIdentity::query()->sole()->only(['user_id', 'subject']))->toBe(['user_id' => $fittingUser->id, 'subject' => str_repeat('g', 255)]);
});
