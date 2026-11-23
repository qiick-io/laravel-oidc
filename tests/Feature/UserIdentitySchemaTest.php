<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Qiick\Oidc\Models\UserIdentity;

/*
 * M1 / M3: enriched user_identities create migration and HasUuids public_id.
 * CI runs this file on SQLite, MySQL, MariaDB and PostgreSQL through DB_CONNECTION.
 */

it('creates every enriched user_identities column', function (): void {
    $columns = Schema::getColumnListing('user_identities');

    expect($columns)->toContain(
        'id',
        'public_id',
        'user_id',
        'issuer',
        'subject',
        'subject_type',
        'provider_key',
        'link_method',
        'email_at_link',
        'email_verified_at_link',
        'preferred_username_at_link',
        'name_at_link',
        'last_login_at',
        'last_auth_time_at',
        'last_acr',
        'last_amr',
        'last_id_token_alg',
        'format_version',
        'metadata',
        'created_at',
        'updated_at',
    );
});

it('assigns a UUID v7 public_id and defaults format_version to 1 on create', function (): void {
    $identity = linkIdentity(localUser());

    expect($identity->public_id)->not->toBeEmpty()
        ->and(Str::isUuid($identity->public_id))->toBeTrue()
        ->and(Str::isUuid($identity->public_id, 7))->toBeTrue()
        ->and($identity->format_version)->toBe(1);
});

it('casts link snapshots, last login auth metadata and timestamps', function (): void {
    $identity = linkIdentity(localUser());
    $identity->forceFill([
        'email_verified_at_link' => true,
        'preferred_username_at_link' => 'ada',
        'name_at_link' => 'Ada Lovelace',
        'last_login_at' => '2026-11-22 12:00:00',
        'last_auth_time_at' => '2026-11-22 11:59:00',
        'last_acr' => 'urn:mace:incommon:iap:silver',
        'last_amr' => ['pwd', 'mfa'],
        'last_id_token_alg' => 'RS256',
        'metadata' => ['source' => 'test'],
    ])->save();

    $identity->refresh();

    expect($identity->email_verified_at_link)->toBeTrue()
        ->and($identity->preferred_username_at_link)->toBe('ada')
        ->and($identity->name_at_link)->toBe('Ada Lovelace')
        ->and($identity->last_login_at)->toBeInstanceOf(CarbonImmutable::class)
        ->and($identity->last_auth_time_at)->toBeInstanceOf(CarbonImmutable::class)
        ->and($identity->last_acr)->toBe('urn:mace:incommon:iap:silver')
        ->and($identity->last_amr)->toBe(['pwd', 'mfa'])
        ->and($identity->last_id_token_alg)->toBe('RS256')
        ->and($identity->metadata)->toBe(['source' => 'test']);
});

it('refuses a second row with the same public_id', function (): void {
    $first = linkIdentity(localUser('first@example.com'));
    $secondUser = localUser('second@example.com');

    expect(fn () => UserIdentity::query()->create([
        'public_id' => $first->public_id,
        'user_id' => $secondUser->id,
        'issuer' => 'https://idp.example.com/realms/other',
        'subject' => 'other-subject',
    ]))->toThrow(QueryException::class);
});

it('refuses a second identity of the same issuer for one user', function (): void {
    $user = localUser();
    linkIdentity($user, 'subject-1');

    expect(fn () => linkIdentity($user, 'subject-2'))->toThrow(UniqueConstraintViolationException::class);
});
