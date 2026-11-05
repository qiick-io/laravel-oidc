<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Qiick\Oidc\Contracts\UserProvisioningContract;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Enums\LoginRefusalReasonEnum;
use Qiick\Oidc\Events\OidcIdentityLinkedEvent;
use Qiick\Oidc\Events\OidcLoginSucceededEvent;
use Qiick\Oidc\Events\OidcUserProvisionedEvent;
use Qiick\Oidc\Models\UserIdentity;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Services\RpInitiatedLogoutService;
use Qiick\Oidc\Tests\Support\User;

beforeEach(function (): void {
    Event::fake([OidcLoginSucceededEvent::class, OidcIdentityLinkedEvent::class, OidcUserProvisionedEvent::class]);
});

it('signs in the user linked to (issuer, sub), whatever the email says', function (): void {
    $identityProvider = fakeProvider();
    $user = localUser();
    $identity = linkIdentity($user, 'user-42');

    ssoLogin($this, $identityProvider, ['sub' => 'user-42', 'email' => 'changed@elsewhere.example'])->assertRedirect('/');

    expect(auth()->id())->toBe($user->id)
        ->and($identity->refresh()->last_login_at)->not->toBeNull()
        ->and(app(IdentitySessionService::class)->current(session()->driver())?->subject)->toBe('user-42');

    Event::assertDispatched(OidcLoginSucceededEvent::class, fn (OidcLoginSucceededEvent $event): bool => $event->user->is($user));
});

it('regenerates the session and sets no remember cookie by default', function (): void {
    $identityProvider = fakeProvider();
    linkIdentity(localUser());
    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->headers->get('Location');
    $sessionIdBeforeLogin = session()->getId();

    $response = $this->get($identityProvider->authorize($authorizationUrl));

    expect(session()->getId())->not->toBe($sessionIdBeforeLogin);
    expect(collect($response->headers->getCookies())->map->getName()->filter(fn (string $name): bool => str_starts_with($name, 'remember_')))->toBeEmpty();
});

it('sets a remember cookie when oidc.remember is on', function (): void {
    $identityProvider = fakeProvider(['remember' => true]);
    linkIdentity(localUser());

    $response = ssoLogin($this, $identityProvider);

    expect(collect($response->headers->getCookies())->map->getName()->filter(fn (string $name): bool => str_starts_with($name, 'remember_')))->not->toBeEmpty();
});

it('refuses an unknown identity when auto-link and JIT are off, even with a matching email', function (): void {
    localUser('sso.user@example.com');

    assertRefused(ssoLogin($this, fakeProvider()), LoginRefusalReasonEnum::NoLinkedUser);
    expect(UserIdentity::query()->count())->toBe(0);
});

it('auto-links an existing user by verified email, case-insensitively', function (): void {
    $user = localUser('Ada@Example.com');

    ssoLogin($this, fakeProvider(['auto_link' => true]), ['sub' => 'user-42', 'email' => 'ada@EXAMPLE.com'])->assertRedirect('/');

    expect(auth()->id())->toBe($user->id)
        ->and(UserIdentity::query()->sole()->only(['user_id', 'subject', 'email_at_link']))
        ->toBe(['user_id' => $user->id, 'subject' => 'user-42', 'email_at_link' => 'ada@example.com']);

    Event::assertDispatched(OidcIdentityLinkedEvent::class);
});

it('never auto-links or provisions from an unverified email', function (array $configOverrides, mixed $emailVerified): void {
    localUser('sso.user@example.com');

    assertRefused(ssoLogin($this, fakeProvider($configOverrides), ['email_verified' => $emailVerified]), LoginRefusalReasonEnum::EmailNotVerified);
})->with([
    'auto-link, false' => [['auto_link' => true], false],
    'auto-link, missing (Entra)' => [['auto_link' => true], null],
    'auto-link, string false' => [['auto_link' => true], 'false'],
    'JIT, false' => [['jit' => true], false],
]);

it('accepts the string "true" as a verified email', function (): void {
    localUser('sso.user@example.com');

    ssoLogin($this, fakeProvider(['auto_link' => true]), ['email_verified' => 'true'])->assertRedirect('/');
});

it('links without email_verified when require_verified_email is off (Entra ID)', function (): void {
    $user = localUser('sso.user@example.com');

    ssoLogin($this, fakeProvider(['auto_link' => true, 'require_verified_email' => false]), ['email_verified' => null])->assertRedirect('/');

    expect(auth()->id())->toBe($user->id);
});

it('refuses a login without a usable email when linking is needed', function (mixed $email): void {
    assertRefused(ssoLogin($this, fakeProvider(['auto_link' => true, 'jit' => true]), ['email' => $email]), LoginRefusalReasonEnum::EmailMissing);
})->with([null, '', 'not-an-email']);

it('does not auto-link a user already linked to another identity of the same issuer', function (): void {
    $user = localUser('sso.user@example.com');
    linkIdentity($user, 'the-original-subject');

    assertRefused(ssoLogin($this, fakeProvider(['auto_link' => true]), ['sub' => 'an-attacker-subject']), LoginRefusalReasonEnum::LinkedToAnotherIdentity);
});

it('auto-links a user linked only at another issuer', function (): void {
    $user = localUser('sso.user@example.com');
    linkIdentity($user, 'fake-subject-1', 'https://old-idp.example.com');

    ssoLogin($this, fakeProvider(['auto_link' => true]))->assertRedirect('/');

    expect(auth()->id())->toBe($user->id)->and(UserIdentity::query()->count())->toBe(2);
});

it('never duplicates an existing account through JIT when auto-link is off', function (): void {
    localUser('sso.user@example.com');

    assertRefused(ssoLogin($this, fakeProvider(['jit' => true])), LoginRefusalReasonEnum::AccountNotLinked);
    expect(User::query()->count())->toBe(1);
});

it('provisions a new user just in time and reuses it on the next login', function (): void {
    $identityProvider = fakeProvider(['jit' => true]);

    ssoLogin($this, $identityProvider, ['email' => 'New.User@Example.com', 'name' => 'New User'])->assertRedirect('/');

    $user = User::query()->sole();
    expect($user->only(['name', 'email']))->toBe(['name' => 'New User', 'email' => 'new.user@example.com'])
        ->and($user->email_verified_at)->not->toBeNull()
        ->and(auth()->id())->toBe($user->id);
    Event::assertDispatched(OidcUserProvisionedEvent::class);

    auth()->logout();
    ssoLogin($this, $identityProvider, ['email' => 'new.user@example.com'])->assertRedirect('/');

    expect(User::query()->count())->toBe(1)->and(UserIdentity::query()->count())->toBe(1);
});

it('provisions only allowed email domains', function (): void {
    $identityProvider = fakeProvider(['jit' => true, 'allowed_domains' => ['Example.com']]);

    assertRefused(ssoLogin($this, $identityProvider, ['email' => 'mallory@evil.example']), LoginRefusalReasonEnum::DomainNotAllowed);

    ssoLogin($this, $identityProvider, ['sub' => 'other', 'email' => 'ok@example.com'])->assertRedirect('/');
    expect(User::query()->count())->toBe(1);
});

it('does not treat LIKE wildcards in an email as a match', function (): void {
    $victim = localUser('axb@example.com');

    ssoLogin($this, fakeProvider(['auto_link' => true, 'jit' => true]), ['email' => 'a_b@example.com'])->assertRedirect('/');

    expect(auth()->id())->not->toBe($victim->id)
        ->and(UserIdentity::query()->where('user_id', $victim->id)->exists())->toBeFalse();
});

it('uses the app provisioning when bound', function (): void {
    app()->bind(UserProvisioningContract::class, fn () => new class implements UserProvisioningContract
    {
        public function provision(AuthenticatedIdentityData $identity, string $email): User
        {
            return localUser($email, ['name' => 'Provisioned by the app']);
        }
    });

    ssoLogin($this, fakeProvider(['jit' => true]))->assertRedirect('/');

    expect(User::query()->sole()->name)->toBe('Provisioned by the app');
});

it('refuses inactive users', function (array $configOverrides, Closure $prepareUser): void {
    Schema::table('users', fn (Blueprint $table) => $table->boolean('is_active')->default(true));
    $prepareUser();

    assertRefused(ssoLogin($this, fakeProvider(['users.active_column' => 'is_active', ...$configOverrides])), LoginRefusalReasonEnum::InactiveUser);
})->with([
    'linked' => [[], fn () => linkIdentity(localUser(attributes: ['is_active' => false]))],
    'auto-linked' => [['auto_link' => true], fn () => localUser('sso.user@example.com', ['is_active' => false])],
]);

it('sends protocol failures back to the login page with a generic message', function (): void {
    fakeProvider();
    $this->get('/auth/oidc/redirect');

    $this->get('/auth/oidc/callback?code=stolen&state=forged')
        ->assertRedirect('/login')
        ->assertSessionHasErrors(['email' => 'SSO login failed. Try again or use email and password.']);
});

it('answers 404 on both routes while SSO is off', function (): void {
    $this->get('/auth/oidc/redirect')->assertNotFound();
    $this->get('/auth/oidc/callback')->assertNotFound();
});

it('keeps signed-in users away from the SSO routes', function (): void {
    fakeProvider();

    $this->actingAs(localUser())->get('/auth/oidc/redirect')->assertRedirect();
    expect(session()->has('oidc.pending_logins'))->toBeFalse();
});

it('cycles the remember token of the linked user on a back-channel logout', function (): void {
    $identityProvider = fakeProvider();
    $user = localUser(attributes: ['remember_token' => 'old-remember-token']);
    linkIdentity($user);

    $this->post('/auth/oidc/backchannel-logout', [
        'logout_token' => $identityProvider->sign($identityProvider->logoutTokenClaims(['sid' => null])),
    ])->assertOk();

    expect($user->refresh()->remember_token)->not->toBe('old-remember-token')->toHaveLength(60);
});

it('logs in through the routes and logs out at the IdP afterwards', function (): void {
    $identityProvider = fakeProvider();
    linkIdentity(localUser());
    ssoLogin($this, $identityProvider);

    $endSessionUrl = app(RpInitiatedLogoutService::class)->endSessionUrl(session()->driver());

    expect($endSessionUrl)->toStartWith($identityProvider->issuer.'/protocol/openid-connect/logout?id_token_hint=');
});
