<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Qiick\Oidc\Contracts\UserProvisioningContract;
use Qiick\Oidc\Data\AuthenticatedIdentityData;
use Qiick\Oidc\Enums\LoginRefusalReasonEnum;
use Qiick\Oidc\Events\OidcIdentityLinkedEvent;
use Qiick\Oidc\Events\OidcUserProvisionedEvent;
use Qiick\Oidc\Exceptions\LoginRefusedException;
use Qiick\Oidc\Models\UserIdentity;

/**
 * Maps a validated SSO identity to a local user (design section 4, "Linking").
 *
 * 1. (issuer, sub) already linked: that user. The email does not matter.
 * 2. Otherwise, with auto-link on: the local user with the same verified email,
 *    unless that user is already linked to another identity of this issuer.
 *    Auto-link is a per-provider decision, off by default: an IdP that lets
 *    users choose any email would turn it into an account takeover.
 * 3. Otherwise, with JIT on: a new user, if the email domain is allowed. An
 *    existing account with that email is never duplicated.
 * 4. Otherwise the login is refused.
 *
 * Inactive users are always refused.
 */
final readonly class UserLinkingService
{
    /**
     * @param  list<string>  $allowedDomains  lower-case; empty allows all
     */
    public function __construct(
        private UserProvisioningContract $userProvisioning,
        private Dispatcher $events,
        private bool $isAutoLinkEnabled,
        private bool $isJitEnabled,
        private bool $isVerifiedEmailRequired,
        private array $allowedDomains,
        private string $emailColumn,
        private ?string $activeColumn,
    ) {}

    /**
     * @return UserIdentity the linked identity, with its user loaded
     *
     * @throws LoginRefusedException
     */
    public function resolve(AuthenticatedIdentityData $identity): UserIdentity
    {
        $linkedIdentity = UserIdentity::query()
            ->where('issuer', $identity->issuer)
            ->where('subject', $identity->subject)
            ->first();

        if ($linkedIdentity !== null) {
            $this->assertActive($linkedIdentity->user ?? throw new LoginRefusedException(LoginRefusalReasonEnum::NoLinkedUser));

            return $linkedIdentity;
        }

        if (! $this->isAutoLinkEnabled && ! $this->isJitEnabled) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::NoLinkedUser);
        }

        $email = $this->verifiedEmail($identity);
        $existingUser = $this->findUserByEmail($email);

        if ($existingUser !== null) {
            return $this->linkExistingUser($existingUser, $identity, $email);
        }

        if (! $this->isJitEnabled) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::NoLinkedUser);
        }

        return $this->provisionUser($identity, $email);
    }

    /**
     * @throws LoginRefusedException
     */
    private function linkExistingUser(Model&Authenticatable $user, AuthenticatedIdentityData $identity, string $email): UserIdentity
    {
        if (! $this->isAutoLinkEnabled) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::AccountNotLinked);
        }

        $this->assertActive($user);

        $isLinkedToThisIssuer = UserIdentity::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->where('issuer', $identity->issuer)
            ->exists();

        if ($isLinkedToThisIssuer) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::LinkedToAnotherIdentity);
        }

        $linkedIdentity = $this->createIdentity($user, $identity, $email, 'auto_link_email');
        $this->events->dispatch(new OidcIdentityLinkedEvent($user, $identity));

        return $linkedIdentity;
    }

    /**
     * @throws LoginRefusedException
     */
    private function provisionUser(AuthenticatedIdentityData $identity, string $email): UserIdentity
    {
        $domain = substr($email, (int) strrpos($email, '@') + 1);

        if ($this->allowedDomains !== [] && ! in_array($domain, $this->allowedDomains, true)) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::DomainNotAllowed);
        }

        [$user, $linkedIdentity] = DB::transaction(function () use ($identity, $email): array {
            $user = $this->userProvisioning->provision($identity, $email);

            return [$user, $this->createIdentity($user, $identity, $email, 'jit')];
        });

        $this->assertActive($user);
        $this->events->dispatch(new OidcUserProvisionedEvent($user, $identity));

        return $linkedIdentity;
    }

    /**
     * Snapshot link-time profile claims onto the new row (standards review M1/M2).
     * Trust-sensitive login metadata is written later on every login.
     */
    private function createIdentity(
        Model&Authenticatable $user,
        AuthenticatedIdentityData $identity,
        string $email,
        string $linkMethod,
    ): UserIdentity {
        $preferredUsername = $identity->claim('preferred_username');
        $displayName = $identity->claim('name');
        $emailVerified = $identity->claim('email_verified');

        $linkedIdentity = UserIdentity::query()->create([
            'user_id' => $user->getAuthIdentifier(),
            'issuer' => $identity->issuer,
            'subject' => $identity->subject,
            'link_method' => $linkMethod,
            'email_at_link' => $email,
            'email_verified_at_link' => $emailVerified === true || $emailVerified === 'true'
                ? true
                : ($emailVerified === false || $emailVerified === 'false' ? false : null),
            'preferred_username_at_link' => is_string($preferredUsername) && $preferredUsername !== ''
                ? $preferredUsername
                : null,
            'name_at_link' => is_string($displayName) && $displayName !== '' ? $displayName : null,
        ]);

        return $linkedIdentity->setRelation('user', $user);
    }

    /**
     * The lower-cased email claim, checked against `email_verified` (OIDC Core
     * 5.1). Some IdPs send the flag as the string "true".
     *
     * @throws LoginRefusedException
     */
    private function verifiedEmail(AuthenticatedIdentityData $identity): string
    {
        $email = $identity->claim('email');

        if (! is_string($email) || filter_var(trim($email), FILTER_VALIDATE_EMAIL) === false) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::EmailMissing);
        }

        $emailVerified = $identity->claim('email_verified');
        $isEmailVerified = $emailVerified === true || $emailVerified === 'true';

        if ($this->isVerifiedEmailRequired && ! $isEmailVerified) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::EmailNotVerified);
        }

        return mb_strtolower(trim($email));
    }

    /**
     * Case-insensitive email lookup on any database. LIKE narrows the
     * candidates (its `_` and `%` wildcards can only add candidates); the exact
     * comparison in PHP decides, so `a_b@example.com` never matches `axb@...`.
     */
    private function findUserByEmail(string $email): (Model&Authenticatable)|null
    {
        /** @var (Model&Authenticatable)|null */
        return UserIdentity::userModel()::query()
            ->whereLike($this->emailColumn, $email, caseSensitive: false)
            ->get()
            ->first(fn (Model $candidate): bool => is_string($candidateEmail = $candidate->getAttribute($this->emailColumn))
                && mb_strtolower($candidateEmail) === $email);
    }

    /**
     * @throws LoginRefusedException
     */
    private function assertActive(Model $user): void
    {
        if ($this->activeColumn !== null && ! (bool) $user->getAttribute($this->activeColumn)) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::InactiveUser);
        }
    }
}
