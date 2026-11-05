<?php

declare(strict_types=1);

use Qiick\Oidc\Contracts\RoleSynchronizationContract;
use Qiick\Oidc\Services\SpatieRoleSynchronizationService;
use Qiick\Oidc\Testing\FakeIdentityProvider;
use Qiick\Oidc\Tests\Support\RecordingRoleSynchronization;
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

it('synchronizes Spatie-style roles without touching unmanaged ones', function (): void {
    $user = new UserWithRoles;
    $user->roleNames = ['super-admin', 'editor', 'auditor'];

    (new SpatieRoleSynchronizationService)->synchronize($user, ['admin', 'ghost'], ['admin', 'editor', 'ghost']);

    expect($user->roleNames)->toBe(['super-admin', 'auditor', 'admin']);
});
