<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Date;
use Qiick\Oidc\Contracts\SecondFactorChallengeContract;
use Qiick\Oidc\Services\BackChannelLogoutService;
use Qiick\Oidc\Services\FortifySecondFactorChallengeService;
use Qiick\Oidc\Services\IdentitySessionService;
use Qiick\Oidc\Services\SessionRevocationService;
use Qiick\Oidc\Tests\Support\User;
use Symfony\Component\HttpFoundation\Response;

/**
 * The app's second factor as a test double: required for every user, and
 * every user has one to challenge, unless $hasSecondFactor is false.
 */
function bindAppSecondFactor(bool $isRequired = true, bool $hasSecondFactor = true): void
{
    app()->instance(SecondFactorChallengeContract::class, new readonly class($isRequired, $hasSecondFactor) implements SecondFactorChallengeContract
    {
        public function __construct(private bool $isRequired, private bool $hasSecondFactor) {}

        public function isRequired(Model&Authenticatable $user): bool
        {
            return $this->isRequired;
        }

        public function challenge(Request $request, Model&Authenticatable $user, bool $shouldRemember): ?Response
        {
            if (! $this->hasSecondFactor) {
                return null;
            }

            $request->session()->put('login.id', $user->getKey());

            return new RedirectResponse('/two-factor-challenge');
        }
    });
}

beforeEach(function (): void {
    $this->user = localUser();
    linkIdentity($this->user);
});

it('signs in directly when the app does not require 2FA', function (): void {
    bindAppSecondFactor(isRequired: false);

    ssoLogin($this, fakeProvider(), ['amr' => ['pwd']])->assertRedirect('/');

    expect(auth()->id())->toBe($this->user->id);
});

it('accepts MFA proven by the IdP', function (array $configOverrides, array $claims): void {
    bindAppSecondFactor();

    ssoLogin($this, fakeProvider($configOverrides), $claims)->assertRedirect('/');

    expect(auth()->id())->toBe($this->user->id);
})->with([
    'amr mfa (RFC 8176)' => [[], ['amr' => ['pwd', 'mfa']]],
    'amr otp when accepted' => [['mfa.amr_values' => ['otp', 'hwk']], ['amr' => ['pwd', 'otp']]],
    'acr when accepted' => [['mfa.acr_values' => ['gold']], ['acr' => 'gold']],
    'signaculum acr mfa (default)' => [[], ['acr' => 'urn:qiick:loa:mfa']],
]);

it('runs the app second factor when the IdP did not prove MFA', function (array $claims): void {
    bindAppSecondFactor();

    ssoLogin($this, fakeProvider(['mfa.acr_values' => ['gold']]), $claims)->assertRedirect('/two-factor-challenge');

    expect(auth()->check())->toBeFalse()
        ->and(session('login.id'))->toBe($this->user->id)
        ->and(session(IdentitySessionService::SESSION_KEY))->toBeNull()
        ->and(session(IdentitySessionService::PENDING_SESSION_KEY.'.user_id'))->toBe($this->user->id);
})->with([
    'no amr' => [[]],
    'password only' => [['amr' => ['pwd']]],
    'amr not a list' => [['amr' => 'mfa']],
    'other acr' => [['acr' => 'silver']],
    'signaculum password acr' => [['acr' => 'urn:qiick:loa:pwd']],
]);

it('never trusts amr from the unsigned userinfo response', function (): void {
    bindAppSecondFactor();
    $identityProvider = fakeProvider();
    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->headers->get('Location');

    $this->get($identityProvider->authorize($authorizationUrl, ['amr' => ['pwd']], ['amr' => ['mfa'], 'acr' => 'gold']))
        ->assertRedirect('/two-factor-challenge');
});

it('completes the SSO session when the challenge signs the same user in', function (): void {
    bindAppSecondFactor();
    ssoLogin($this, fakeProvider());

    Auth::login($this->user);

    expect(app(IdentitySessionService::class)->current(session()->driver())?->subject)->toBe('fake-subject-1')
        ->and(session()->has(IdentitySessionService::PENDING_SESSION_KEY))->toBeFalse();
});

it('drops the pending identity when another user signs in or it expired', function (string $case): void {
    bindAppSecondFactor();
    ssoLogin($this, fakeProvider());

    if ($case === 'expired') {
        Date::setTestNow(Date::now()->addSeconds(IdentitySessionService::PENDING_SECONDS + 1));
        Auth::login($this->user);
    } else {
        Auth::login(localUser('someone.else@example.com'));
    }

    expect(app(IdentitySessionService::class)->current(session()->driver()))->toBeNull()
        ->and(session()->has(IdentitySessionService::PENDING_SESSION_KEY))->toBeFalse();
})->with(['another user', 'expired']);

it('signs in when the user has no second factor to challenge', function (): void {
    bindAppSecondFactor(hasSecondFactor: false);

    ssoLogin($this, fakeProvider())->assertRedirect('/');

    expect(auth()->id())->toBe($this->user->id);
});

it('asks the IdP for a stronger login when configured', function (): void {
    fakeProvider(['mfa.request_acr_values' => 'gold']);

    $authorizationUrl = (string) $this->get('/auth/oidc/redirect')->headers->get('Location');

    expect(queryParameters($authorizationUrl)['acr_values'])->toBe('gold');
});

it('has nothing to challenge without Fortify', function (): void {
    $service = new FortifySecondFactorChallengeService(isRequiredByDefault: true);
    $request = browserRequest('http://localhost/auth/oidc/callback', browserSession());

    expect($service->isRequired($this->user))->toBeTrue()
        ->and($service->challenge($request, $this->user, false))->toBeNull()
        ->and((new FortifySecondFactorChallengeService(false))->isRequired($this->user))->toBeFalse();
});

it('keeps a sub-only logout received during the app challenge effective after the challenge', function (): void {
    bindAppSecondFactor();
    $identityProvider = fakeProvider();
    Date::setTestNow(Date::now()->startOfSecond());

    ssoLogin($this, $identityProvider, ['amr' => ['pwd']])->assertRedirect('/two-factor-challenge');

    // BCL §2.6: a logout naming only `sub` ends every session of that user
    // authenticated at or before it, including one still in the app's 2FA.
    Date::setTestNow(Date::now()->addSeconds(10));
    app(BackChannelLogoutService::class)->handle(
        $identityProvider->sign($identityProvider->logoutTokenClaims(['sid' => null]), ['typ' => 'logout+jwt']),
    );

    Date::setTestNow(Date::now()->addSeconds(20));
    Auth::login($this->user);

    $identity = app(IdentitySessionService::class)->current(session()->driver());

    expect($identity)->not->toBeNull()
        ->and(app(SessionRevocationService::class)->isRevoked($identity))->toBeTrue();
});

it('keeps the callback time as the session authentication time after the challenge', function (): void {
    bindAppSecondFactor();
    Date::setTestNow(Date::now()->startOfSecond());
    $callbackTime = Date::now()->getTimestamp();

    ssoLogin($this, fakeProvider(), ['amr' => ['pwd']]);
    Date::setTestNow(Date::now()->addSeconds(30));
    Auth::login($this->user);

    expect(app(IdentitySessionService::class)->current(session()->driver())?->authenticatedAt)->toBe($callbackTime);
});

it('waits ten minutes for the app challenge, to the second', function (int $secondsLater, bool $isPromoted): void {
    bindAppSecondFactor();
    Date::setTestNow(Date::now()->startOfSecond());
    ssoLogin($this, fakeProvider());

    Date::setTestNow(Date::now()->addSeconds($secondsLater));
    Auth::login($this->user);

    expect(app(IdentitySessionService::class)->current(session()->driver()) !== null)->toBe($isPromoted);
})->with([
    'at 600 seconds' => [600, true],
    'at 601 seconds' => [601, false],
]);

it('promotes a pending identity for a string user key and ignores a malformed one', function (mixed $pendingUserId, bool $isPromoted): void {
    $session = session()->driver();
    $session->put(IdentitySessionService::PENDING_SESSION_KEY, [
        'user_id' => $pendingUserId,
        'expires_at' => Date::now()->getTimestamp() + 60,
        'identity' => [
            'issuer' => 'https://idp.example.com/realms/test',
            'subject' => 'user-42',
            'id_token' => 'header.payload.signature',
            'authenticated_at' => Date::now()->getTimestamp(),
        ],
    ]);

    app(IdentitySessionService::class)->promotePending($session, 'user-uuid-1');

    expect(app(IdentitySessionService::class)->current($session) !== null)->toBe($isPromoted)
        ->and($session->has(IdentitySessionService::PENDING_SESSION_KEY))->toBeFalse();
})->with([
    'same string key' => ['user-uuid-1', true],
    'not a scalar' => [['user-uuid-1'], false],
    'missing' => [null, false],
]);
