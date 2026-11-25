<?php

declare(strict_types=1);

use Qiick\Oidc\Data\PersonNameData;

/*
 * Given and family names from the standard claims (OIDC Core 5.1), for apps
 * with first_name / last_name columns: given_name and family_name when the
 * IdP sends them, else `name` split with its last word as the family name.
 */

it('reads the name from the claims', function (array $claims, ?array $expected): void {
    $personName = PersonNameData::fromClaims($claims);

    expect($personName === null ? null : [$personName->givenName, $personName->familyName, $personName->fullName()])->toBe($expected);
})->with([
    'given and family name' => [['given_name' => ' Ada ', 'family_name' => ' Lovelace '], ['Ada', 'Lovelace', 'Ada Lovelace']],
    'given name only' => [['given_name' => 'Ada'], ['Ada', '', 'Ada']],
    'name of two words' => [['name' => 'Ada Lovelace'], ['Ada', 'Lovelace', 'Ada Lovelace']],
    'name of three words, extra spaces' => [['name' => '  Ada   King  Lovelace '], ['Ada King', 'Lovelace', 'Ada King Lovelace']],
    'name of one word' => [['name' => 'Ada'], ['Ada', '', 'Ada']],
    'blank given name falls back to name' => [['given_name' => '  ', 'name' => 'Grace Hopper'], ['Grace', 'Hopper', 'Grace Hopper']],
    'family name not a string' => [['given_name' => 'Ada', 'family_name' => 42], ['Ada', '', 'Ada']],
    'blank name' => [['name' => '   '], null],
    'no name claims' => [[], null],
    'name not a string' => [['name' => ['Ada']], null],
]);
