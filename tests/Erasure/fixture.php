<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Qiick\Oidc\Data\LogoutTokenData;
use Qiick\Oidc\Erasure\OidcEraser;
use Qiick\Oidc\Models\OidcLogoutRevocation;
use Qiick\Oidc\Models\UserIdentity;
use Qiick\Oidc\Services\SessionRevocationService;
use Qiick\Oidc\Tests\Support\User;
use Qiick\Standards\Erasure\Support\ErasureFixture;
use Qiick\Standards\Erasure\Support\ErasurePerson;

/**
 * Exercises both package tables. SessionRevocationService writes the two
 * personal cache keys, `oidc:revoked-sub:<sha256>` and `oidc:revoked-sid:<sha256>`,
 * on the named OIDC cache store. Login state markers store only a random,
 * single-use transaction key. Discovery and JWKS describe the provider. The
 * product owns the session store.
 *
 * SID is personal whenever a subject corroborates it, which is what this
 * fixture seeds. The report's cleartext SID entry counts unresolved rows
 * across affected issuers because those rows cannot be assigned to a person.
 */
return new class implements ErasureFixture
{
    private const string ISSUER = 'https://identity.example.test';

    private const string CACHE_STORE = 'oidc-erasure-fixture';

    public function packageName(): string
    {
        return 'qiick/laravel-oidc';
    }

    public function eraserClass(): string
    {
        return OidcEraser::class;
    }

    public function connectionName(): ?string
    {
        return null;
    }

    public function tables(): array
    {
        return [
            'user_identities' => [
                'id' => 'other',
                'public_id' => 'personal',
                'user_id' => 'personal',
                'issuer' => 'other',
                'subject' => 'personal',
                'subject_type' => 'personal',
                'provider_key' => 'personal',
                'link_method' => 'personal',
                'email_at_link' => 'personal',
                'email_verified_at_link' => 'personal',
                'preferred_username_at_link' => 'personal',
                'name_at_link' => 'personal',
                'last_login_at' => 'personal',
                'last_auth_time_at' => 'personal',
                'last_acr' => 'personal',
                'last_amr' => 'personal',
                'last_id_token_alg' => 'personal',
                'format_version' => 'other',
                'metadata' => 'personal',
                'created_at' => 'personal',
                'updated_at' => 'personal',
            ],
            'oidc_logout_revocations' => [
                'id' => 'other',
                'issuer' => 'other',
                'sid' => 'personal',
                'sub' => 'personal',
                'jti' => 'personal',
                'replay_key' => 'retained',
                'channel' => 'other',
                'received_at' => 'other',
                'expires_at' => 'other',
                'metadata' => 'personal',
                'created_at' => 'other',
                'updated_at' => 'other',
            ],
        ];
    }

    public function retainedCleartextColumns(): array
    {
        return ['oidc_logout_revocations.replay_key' => 'security_log'];
    }

    public function diskPaths(ErasurePerson $person): array
    {
        return [];
    }

    public function additionalConnections(): array
    {
        return [];
    }

    public function makePerson(): ErasurePerson
    {
        Config::set([
            'cache.stores.'.self::CACHE_STORE => ['driver' => 'array'],
            'oidc.cache.store' => self::CACHE_STORE,
        ]);

        $nextUserId = max(100_001, (int) User::query()->max('id') + 1);
        $person = ErasurePerson::fresh((string) $nextUserId);
        localUser($person->identifiers[0], ['id' => $nextUserId, 'name' => $person->identifiers[2]]);

        return $person;
    }

    public function seed(ErasurePerson $person, ?string $organisationId): void
    {
        [$email, $username, $name] = $person->identifiers;
        $authenticationTime = Date::parse('2026-01-01')->addSeconds((int) $person->userId);

        UserIdentity::query()->create([
            'user_id' => $person->userId,
            'public_id' => $person->publicIds[0],
            'issuer' => self::ISSUER,
            'subject' => $person->userPublicId,
            'subject_type' => 'public',
            'provider_key' => 'probe-provider',
            'link_method' => 'probe-link',
            'email_at_link' => $email,
            'email_verified_at_link' => true,
            'preferred_username_at_link' => $username,
            'name_at_link' => $name,
            'last_login_at' => $authenticationTime,
            'last_auth_time_at' => $authenticationTime,
            'last_acr' => 'probe-acr',
            'last_amr' => ['pwd', 'otp'],
            'last_id_token_alg' => 'RS256',
            'metadata' => ['profile' => $person->otherPersonalValues],
            'created_at' => $authenticationTime,
            'updated_at' => $authenticationTime,
        ]);

        $sessionId = 'session-'.$person->userPublicId;
        $revoker = app(SessionRevocationService::class);
        $revoker->revoke(new LogoutTokenData(self::ISSUER, $person->userPublicId, null, 'subject-'.$username));
        $revoker->revoke(new LogoutTokenData(self::ISSUER, $person->userPublicId, $sessionId, 'session-'.$username));
        $revoker->revoke(new LogoutTokenData(self::ISSUER, null, $sessionId, null, channel: 'frontchannel'));

        OidcLogoutRevocation::query()->where('sub', $person->userPublicId)->update(['metadata' => ['name' => $name]]);
    }

    public function supportsOrganisationScope(): bool
    {
        return false;
    }

    public function organisationScopedTables(): array
    {
        return [];
    }

    public function cacheKeys(ErasurePerson $person): array
    {
        return [
            self::CACHE_STORE => [
                SessionRevocationService::cacheKey('sub', self::ISSUER, $person->userPublicId),
                SessionRevocationService::cacheKey('sid', self::ISSUER, 'session-'.$person->userPublicId),
            ],
        ];
    }

    public function call(Closure $erase): object
    {
        return $erase();
    }
};
