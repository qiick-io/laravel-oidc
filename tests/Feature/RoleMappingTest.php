<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Log;
use Qiick\Oidc\Contracts\RoleSynchronizationContract;
use Qiick\Oidc\Services\RoleMappingService;
use Qiick\Oidc\Services\SpatieRoleSynchronizationService;
use Qiick\Oidc\Testing\FakeIdentityProvider;
use Qiick\Oidc\Tests\Support\RecordingRoleSynchronization;
use Qiick\Oidc\Tests\Support\User;
use Qiick\Oidc\Tests\Support\UserWithRoles;

const EXTERNA_ROLE_MAP = [
    'owner' => ['admin', 'super-admin'],
    'admin' => 'admin',
    'member' => 'editor',
    'billing' => 'billing-viewer',
];

/**
 * @param  array<string, mixed>  $roleConfig
 */
function roleMappedProvider(array $roleConfig = []): FakeIdentityProvider
{
    return fakeProvider(['roles' => [
        'enabled' => true,
        'claim' => 'orgs',
        'organization' => 'acme',
        'map' => EXTERNA_ROLE_MAP,
        'forbidden' => [],
        ...$roleConfig,
    ]]);
}

beforeEach(function (): void {
    $this->roleSynchronization = new RecordingRoleSynchronization;
    app()->instance(RoleSynchronizationContract::class, $this->roleSynchronization);
    linkIdentity(localUser());
});

it('maps the roles of the configured organisation and manages only mapped roles', function (): void {
    ssoLogin($this, roleMappedProvider(), ['orgs' => [
        ['id' => 'org-1', 'slug' => 'acme', 'roles' => ['member', 'billing', 'unknown-role', 42]],
        ['id' => 'org-2', 'slug' => 'other', 'roles' => ['owner']],
    ]])->assertRedirect('/');

    expect($this->roleSynchronization->calls)->toBe([[
        'granted' => ['billing-viewer', 'editor'],
        'managed' => ['admin', 'billing-viewer', 'editor'],
    ]]);
});

it('matches the organisation by id as well as by slug', function (): void {
    ssoLogin($this, roleMappedProvider(['organization' => 'org-1']), ['orgs' => [['id' => 'org-1', 'slug' => 'acme', 'roles' => ['admin']]]]);

    expect($this->roleSynchronization->calls[0]['granted'])->toBe(['admin']);
});

it('never grants super-admin, even when the map asks for it', function (): void {
    ssoLogin($this, roleMappedProvider(['map' => ['owner' => 'super-admin', 'admin' => 'admin']]), ['orgs' => [['slug' => 'acme', 'roles' => ['owner', 'admin']]]]);

    expect($this->roleSynchronization->calls)->toBe([['granted' => ['admin'], 'managed' => ['admin']]]);
});

it('never grants a configured forbidden role', function (): void {
    ssoLogin($this, roleMappedProvider(['forbidden' => ['admin']]), ['orgs' => [['slug' => 'acme', 'roles' => ['owner', 'member']]]]);

    expect($this->roleSynchronization->calls[0])->toBe(['granted' => ['editor'], 'managed' => ['billing-viewer', 'editor']]);
});

it('revokes the managed roles when the user left the organisation', function (): void {
    ssoLogin($this, roleMappedProvider(), ['orgs' => [['slug' => 'other', 'roles' => ['owner']]]]);

    expect($this->roleSynchronization->calls[0]['granted'])->toBe([]);
});

it('leaves local roles alone without the claim, when disabled or with a malformed claim', function (array $roleConfig, array $claims): void {
    ssoLogin($this, roleMappedProvider($roleConfig), $claims)->assertRedirect('/');

    expect($this->roleSynchronization->calls)->toBe([]);
})->with([
    'no claim' => [[], []],
    'claim not a list' => [[], ['orgs' => 'acme:admin']],
    'disabled' => [['enabled' => false], ['orgs' => [['slug' => 'acme', 'roles' => ['admin']]]]],
    'empty map' => [['map' => []], ['orgs' => [['slug' => 'acme', 'roles' => ['admin']]]]],
]);

it('reads a flat role claim at a nested path (Keycloak realm roles)', function (): void {
    ssoLogin($this, roleMappedProvider(['claim' => 'realm_access.roles', 'organization' => null]), [
        'realm_access' => ['roles' => ['admin', 'offline_access']],
    ]);

    expect($this->roleSynchronization->calls[0]['granted'])->toBe(['admin']);
});

it('reads role names from a Zitadel-style map claim', function (): void {
    ssoLogin($this, roleMappedProvider([
        'claim' => 'urn:zitadel:iam:org:project:roles',
        'organization' => null,
    ]), [
        'urn:zitadel:iam:org:project:roles' => [
            'member' => ['201982826478953724' => 'zitadel.localhost'],
            'offline_access' => ['201982826478953724' => 'zitadel.localhost'],
        ],
    ]);

    expect($this->roleSynchronization->calls[0]['granted'])->toBe(['editor']);
});

it('synchronizes Spatie-style roles without touching unmanaged ones', function (): void {
    $user = new UserWithRoles;
    $user->roleNames = ['super-admin', 'editor', 'auditor'];

    (new SpatieRoleSynchronizationService)->synchronize($user, ['admin', 'ghost'], ['admin', 'editor', 'ghost']);

    expect($user->roleNames)->toBe(['super-admin', 'auditor', 'admin']);
});

it('grants each app role once, as a list, however many IdP roles map to it', function (): void {
    ssoLogin($this, roleMappedProvider(['map' => ['owner' => 'admin', 'admin' => 'admin', 'member' => 'editor']]), ['orgs' => [
        ['slug' => 'acme', 'roles' => ['owner', 'admin', 'member']],
    ]]);

    expect($this->roleSynchronization->calls[0])->toBe(['granted' => ['admin', 'editor'], 'managed' => ['admin', 'editor']]);
});

it('returns the roles it granted', function (): void {
    $user = localUser('mapped@example.com');
    $identity = completeLogin(roleMappedProvider(), ['orgs' => [['slug' => 'acme', 'roles' => ['member']]]]);

    expect(app(RoleMappingService::class)->apply($user, $identity))->toBe(['editor']);
});

it('reads only string keys that hold a map as Zitadel role names', function (): void {
    ssoLogin($this, roleMappedProvider(['claim' => 'roles', 'organization' => null, 'map' => ['member' => 'editor', 'admin' => 'admin', '' => 'billing-viewer']]), [
        'roles' => ['member' => ['org' => 'example.org'], 'admin' => 'not-a-map', '' => ['org' => 'example.org'], 7 => ['org' => 'example.org']],
    ]);

    expect($this->roleSynchronization->calls[0]['granted'])->toBe(['editor']);
});

it('never reads a string value under a string key as a role name', function (): void {
    ssoLogin($this, roleMappedProvider(['claim' => 'roles', 'organization' => null, 'map' => ['admin' => 'admin', 'member' => 'editor']]), [
        'roles' => ['display' => 'admin', 'member' => ['org' => 'example.org']],
    ]);

    expect($this->roleSynchronization->calls[0]['granted'])->toBe(['editor']);
});

it('reads both role names and Zitadel role keys from one mixed claim', function (): void {
    ssoLogin($this, roleMappedProvider(['claim' => 'roles', 'organization' => null, 'map' => ['member' => 'editor', 'admin' => 'admin']]), [
        'roles' => ['admin', 'member' => ['org' => 'example.org']],
    ]);

    expect($this->roleSynchronization->calls[0]['granted'])->toBe(['admin', 'editor']);
});

it('keeps synchronizing the other roles after one that already matches', function (): void {
    $user = new UserWithRoles;
    $user->roleNames = ['admin'];

    (new SpatieRoleSynchronizationService)->synchronize($user, ['admin', 'editor'], ['admin', 'editor']);

    expect($user->roleNames)->toBe(['admin', 'editor']);
});

it('logs the role it had to skip', function (): void {
    Log::spy();
    $user = new UserWithRoles;

    (new SpatieRoleSynchronizationService)->synchronize($user, ['ghost'], ['ghost']);

    Log::shouldHaveReceived('warning')->withArgs(
        fn (string $message): bool => $message === 'OIDC role mapping skipped the role [ghost]: There is no role named `ghost`.',
    );
});

it('refuses a user model without the three Spatie role methods', function (object $user): void {
    (new SpatieRoleSynchronizationService)->synchronize($user, [], ['admin']);
})->throws(LogicException::class, 'Role mapping needs the Spatie HasRoles trait')->with([
    'no role methods' => fn () => new User,
    'only hasRole' => fn () => new class extends User
    {
        public function hasRole(string $role): bool
        {
            return false;
        }
    },
    'no assignRole' => fn () => new class extends User
    {
        public function hasRole(string $role): bool
        {
            return false;
        }

        public function removeRole(string $role): static
        {
            return $this;
        }
    },
    'no removeRole' => fn () => new class extends User
    {
        public function hasRole(string $role): bool
        {
            return false;
        }

        public function assignRole(string $role): static
        {
            return $this;
        }
    },
]);
