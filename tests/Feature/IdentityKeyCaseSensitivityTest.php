<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Qiick\Oidc\Enums\LoginRefusalReasonEnum;
use Qiick\Oidc\Models\UserIdentity;

/*
 * The identity key (issuer, subject) is opaque and case-sensitive (OIDC Core 2),
 * whatever the database's default collation says. CI runs this file on SQLite,
 * MySQL, MariaDB and PostgreSQL through DB_CONNECTION. Trailing spaces are not
 * left to the collation (PAD SPACE on the MySQL family): an untrimmed `sub` is
 * refused before any lookup.
 */

const LINKED_ISSUER = 'https://idp.example.com/realms/test';

function identityExists(string $issuer, string $subject): bool
{
    return UserIdentity::query()->where('issuer', $issuer)->where('subject', $subject)->exists();
}

it('runs on the connection the environment names', function (): void {
    expect(Schema::getConnection()->getDriverName())->toBe(match (getenv('DB_CONNECTION') ?: 'testing') {
        'testing' => 'sqlite',
        default => getenv('DB_CONNECTION'),
    });
});

it('finds no identity for a subject that differs only in case', function (string $lookupSubject): void {
    linkIdentity(localUser(), 'AbcSubject');

    expect(identityExists(LINKED_ISSUER, 'AbcSubject'))->toBeTrue()
        ->and(identityExists(LINKED_ISSUER, $lookupSubject))->toBeFalse();
})->with(['abcsubject', 'ABCSUBJECT']);

it('finds no identity for an issuer that differs only in case', function (): void {
    linkIdentity(localUser(), 'AbcSubject');

    expect(identityExists('https://idp.example.com/realms/TEST', 'AbcSubject'))->toBeFalse();
});

it('stores two identities of one issuer whose subjects differ only in case', function (): void {
    $firstUser = linkIdentity(localUser('first@example.com'), 'AbcSubject')->user_id;
    $secondUser = linkIdentity(localUser('second@example.com'), 'abcsubject')->user_id;

    expect(UserIdentity::query()->where('subject', 'AbcSubject')->sole()->user_id)->toBe($firstUser)
        ->and(UserIdentity::query()->where('subject', 'abcsubject')->sole()->user_id)->toBe($secondUser);
});

it('does not sign in the user of a subject that differs only in case', function (): void {
    linkIdentity(localUser(), 'AbcSubject');

    assertRefused(ssoLogin($this, fakeProvider(), ['sub' => 'abcsubject']), LoginRefusalReasonEnum::NoLinkedUser);
});

it('refuses and logs a login whose sub is not trimmed, before any lookup', function (string $subject): void {
    linkIdentity(localUser(), 'AbcSubject');
    Log::spy();

    $response = ssoLogin($this, fakeProvider(), ['sub' => $subject]);

    expect(auth()->check())->toBeFalse();
    $response->assertRedirect('/login')->assertSessionHasErrors(['email' => 'SSO login failed. Try again or use email and password.']);
    Log::shouldHaveReceived('warning')->once()->withArgs(
        fn (string $message): bool => $message === 'OIDC login failed: id_token [sub] has leading or trailing whitespace.',
    );
})->with(['AbcSubject ', 'AbcSubject  ', ' AbcSubject']);
