<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Data\LogoutTokenData;
use Qiick\Oidc\Enums\LoginRefusalReasonEnum;
use Qiick\Oidc\Exceptions\InvalidTokenException;
use Qiick\Oidc\Exceptions\LoginRefusedException;
use Qiick\Oidc\Models\OidcLogoutRevocation;
use Qiick\Oidc\Models\UserIdentity;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Services\JwksService;
use Qiick\Oidc\Services\SessionRevocationService;
use Qiick\Oidc\Services\UserLinkingService;
use Qiick\Oidc\Testing\FakeIdentityProvider;
use Qiick\Oidc\Tests\Support\ProcessRace;
use Qiick\Oidc\Tests\Support\User;

/*
 * Races between two real processes with their own database connections: the
 * guarantees below rest on database constraints and atomic inserts, which an
 * in-process test cannot exercise. Skipped on SQLite (one writer, no race).
 */

beforeEach(function (): void {
    if (! ProcessRace::isSupported()) {
        $this->markTestSkipped('Needs PostgreSQL, MySQL or MariaDB and pcntl.');
    }
});

/**
 * True right after the parent's insert into the table: its row exists but is
 * not committed, so the child runs into it.
 */
function afterInsertInto(string $table): Closure
{
    return fn (QueryExecuted $query): bool => str_starts_with($query->sql, 'insert into') && str_contains($query->sql, $table);
}

function firstLoginIdentity(string $subject): AuthenticatedIdentityData
{
    return new AuthenticatedIdentityData(
        'https://idp.example.com/realms/test',
        $subject,
        ['sub' => $subject, 'email' => 'ada@example.com', 'email_verified' => true, 'name' => 'Ada Lovelace'],
        'header.payload.signature',
        'access-token',
        null,
    );
}

it('stores a logout token once when two deliveries of the same jti race', function (): void {
    $logoutToken = new LogoutTokenData('https://idp.example.com/realms/test', 'user-42', 'sid-1', 'jti-1', time() + 120);
    $revoke = function () use ($logoutToken): string {
        app(SessionRevocationService::class)->revoke($logoutToken);

        return 'stored';
    };

    $results = ProcessRace::run(afterInsertInto('oidc_logout_revocations'), $revoke, $revoke);

    expect($results['parent'])->toBe('stored')
        ->and($results['child'])->toBe(['exception' => InvalidTokenException::class, 'message' => 'logout_token [jti] was already used.'])
        ->and(OidcLogoutRevocation::query()->count())->toBe(1);
});

it('provisions one user when two first logins of the same subject race', function (): void {
    config()->set('oidc.jit', true);
    $resolveUserId = fn (): int => (int) app(UserLinkingService::class)->resolve(firstLoginIdentity('user-42'))->user_id;

    $results = ProcessRace::run(afterInsertInto('user_identities'), $resolveUserId, $resolveUserId);

    expect($results['child'])->toBe($results['parent'])
        ->and(User::query()->count())->toBe(1)
        ->and(UserIdentity::query()->count())->toBe(1);
});

it('links a user to one identity of the issuer when two subjects race to auto-link it', function (): void {
    config()->set('oidc.auto_link', true);
    $user = localUser('ada@example.com');

    $resolveUserIdOrRefusal = function (string $subject): int|string {
        try {
            return (int) app(UserLinkingService::class)->resolve(firstLoginIdentity($subject))->user_id;
        } catch (LoginRefusedException $refusal) {
            return $refusal->reason->value;
        }
    };

    $results = ProcessRace::run(
        afterInsertInto('user_identities'),
        fn (): int|string => $resolveUserIdOrRefusal('subject-a'),
        fn (): int|string => $resolveUserIdOrRefusal('subject-b'),
    );

    expect($results['parent'])->toBe($user->id)
        ->and($results['child'])->toBe(LoginRefusalReasonEnum::LinkedToAnotherIdentity->value)
        ->and(UserIdentity::query()->sole()->subject)->toBe('subject-a');
});

it('refetches the JWKS once when two logins meet an unknown kid at the same time', function (): void {
    config()->set('oidc.cache.store', 'database');
    $identityProvider = FakeIdentityProvider::fake();
    $discovery = app(DiscoveryService::class)->discover(app(ProviderConfigurationRepositoryContract::class)->configuration());
    $jwksFetches = fn (): int => Http::recorded(fn (Request $request): bool => $request->url() === $discovery->jwksUri)->count();
    app(JwksService::class)->key($discovery, $identityProvider->jwks()['keys'][0]['kid'], 'RS256');
    $rotatedKeyId = $identityProvider->rotateSigningKey();

    $findRotatedKey = function () use ($discovery, $rotatedKeyId, $jwksFetches): array {
        $fetchesBefore = $jwksFetches();

        try {
            app(JwksService::class)->key($discovery, $rotatedKeyId, 'RS256');
            $isFound = true;
        } catch (InvalidTokenException) {
            $isFound = false;
        }

        return ['isFound' => $isFound, 'fetches' => $jwksFetches() - $fetchesBefore];
    };

    // The parent has read "no refetch yet" for this JWKS and not written its marker.
    $results = ProcessRace::run(
        fn (QueryExecuted $query): bool => str_starts_with($query->sql, 'select')
            && array_filter($query->bindings, fn (mixed $binding): bool => is_string($binding) && str_ends_with($binding, ':refetch')) !== [],
        $findRotatedKey,
        $findRotatedKey,
    );

    expect($results['parent']['fetches'] + $results['child']['fetches'])->toBe(1)
        ->and($results['child'])->toBe(['isFound' => true, 'fetches' => 1])
        ->and($results['parent'])->toBe(['isFound' => false, 'fetches' => 0]);
});
