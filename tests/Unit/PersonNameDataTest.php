<?php

declare(strict_types=1);

use Qiick\Oidc\Data\PersonNameData;

it('builds the person name from the claims', function (array $claims, ?array $expected): void {
    $personName = PersonNameData::fromClaims($claims);

    expect($personName === null ? null : [$personName->givenName, $personName->familyName])->toBe($expected);
})->with([
    'given and family name' => [['given_name' => 'Ada', 'family_name' => 'Lovelace', 'name' => 'Countess Ada'], ['Ada', 'Lovelace']],
    'given name only (no last name)' => [['given_name' => 'Ada', 'name' => 'Ada'], ['Ada', '']],
    'given name wins over name' => [['given_name' => ' Grace ', 'family_name' => ' Hopper ', 'name' => 'G. Hopper'], ['Grace', 'Hopper']],
    'name split, last word is the family name' => [['name' => 'Maria  Luisa   De Rossi'], ['Maria Luisa De', 'Rossi']],
    'one-word name' => [['name' => 'Cher'], ['Cher', '']],
    'empty given name falls back to name' => [['given_name' => ' ', 'name' => 'Ada Lovelace'], ['Ada', 'Lovelace']],
    'non-string claims' => [['given_name' => 42, 'name' => ['Ada']], null],
    'no name at all' => [['email' => 'ada@example.com'], null],
]);

it('joins the full name for single-column apps', function (): void {
    expect((new PersonNameData('Ada', 'Lovelace'))->fullName())->toBe('Ada Lovelace')
        ->and((new PersonNameData('Cher', ''))->fullName())->toBe('Cher');
});
