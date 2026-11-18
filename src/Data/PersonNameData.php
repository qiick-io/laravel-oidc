<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

/**
 * A person's name as apps with first_name / last_name columns need it
 * (Externa, Excubia App, Signaculum).
 *
 * Built from the standard claims (OIDC Core 5.1): `given_name` and
 * `family_name` when the IdP sends `given_name`; otherwise `name` split on
 * whitespace, the last word being the family name. This is the rule agreed
 * with Signaculum, whose own migration splits names the same way. A one-word
 * name has an empty family name.
 */
final readonly class PersonNameData
{
    public function __construct(
        public string $givenName,
        public string $familyName,
    ) {}

    /**
     * Null when the claims carry neither `given_name` nor `name`.
     *
     * @param  array<string, mixed>  $claims
     */
    public static function fromClaims(array $claims): ?self
    {
        $givenName = self::trimmedString($claims['given_name'] ?? null);

        if ($givenName !== '') {
            return new self($givenName, self::trimmedString($claims['family_name'] ?? null));
        }

        $nameParts = preg_split('/\s+/u', self::trimmedString($claims['name'] ?? null), -1, PREG_SPLIT_NO_EMPTY) ?: [];

        if ($nameParts === []) {
            return null;
        }

        $familyName = count($nameParts) > 1 ? (string) array_pop($nameParts) : '';

        return new self(implode(' ', $nameParts), $familyName);
    }

    /**
     * Given and family name joined, for apps with a single name column.
     */
    public function fullName(): string
    {
        return trim($this->givenName.' '.$this->familyName);
    }

    private static function trimmedString(mixed $value): string
    {
        return is_string($value) ? trim($value) : '';
    }
}
