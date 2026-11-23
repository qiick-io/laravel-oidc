<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
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
        $linkedIdentity = $this->linkedIdentity($identity);

        if ($linkedIdentity !== null) {
            return $linkedIdentity;
        }

        try {
            return $this->linkOrProvision($identity);
        } catch (LoginRefusedException|UniqueConstraintViolationException $exception) {
            // A concurrent first login of the same (issuer, sub) may have
            // linked it after the lookup above: this login is then that
            // identity and signs in as its user, like any later login.
            return $this->linkedIdentity($identity) ?? throw $exception;
        }
    }

    /**
     * The identity already linked to (issuer, sub), checked for an active user.
     *
     * @throws LoginRefusedException
     */
    private function linkedIdentity(AuthenticatedIdentityData $identity): ?UserIdentity
    {
        $linkedIdentity = UserIdentity::query()
            ->where('issuer', $identity->issuer)
            ->where('subject', $identity->subject)
            ->first();

        if ($linkedIdentity !== null) {
            $this->assertActive($linkedIdentity->user ?? throw new LoginRefusedException(LoginRefusalReasonEnum::NoLinkedUser));
        }

        return $linkedIdentity;
    }

    /**
     * Steps 2 to 4 of the class docblock, for an (issuer, sub) not linked yet.
     *
     * @throws LoginRefusedException
     * @throws UniqueConstraintViolationException when a concurrent login inserted a conflicting row
     */
    private function linkOrProvision(AuthenticatedIdentityData $identity): UserIdentity
    {
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

        // The check above and this insert are two statements: a concurrent
        // callback can link the user in between. Unique (user_id, issuer)
        // decides, and the loser is refused like the check would have. The
        // transaction is a savepoint inside an app transaction, so PostgreSQL
        // can roll back the failed insert without aborting the outer one.
        try {
            $linkedIdentity = DB::transaction(fn (): UserIdentity => $this->createIdentity($user, $identity, $email, 'auto_link_email'));
        } catch (UniqueConstraintViolationException) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::LinkedToAnotherIdentity);
        }

        $this->events->dispatch(new OidcIdentityLinkedEvent($user, $identity));

        return $linkedIdentity;
    }

    /**
     * @throws LoginRefusedException
     */
    private function provisionUser(AuthenticatedIdentityData $identity, string $email): UserIdentity
    {
        $domain = Str::afterLast($email, '@');

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

        $linkedIdentity = UserIdentity::query()->create([
            'user_id' => $user->getAuthIdentifier(),
            'issuer' => $identity->issuer,
            'subject' => $identity->subject,
            'link_method' => $linkMethod,
            'email_at_link' => $email,
            'email_verified_at_link' => $this->emailVerifiedClaim($identity),
            'preferred_username_at_link' => is_string($preferredUsername) && $preferredUsername !== ''
                ? $preferredUsername
                : null,
            'name_at_link' => is_string($displayName) && $displayName !== '' ? $displayName : null,
        ]);

        return $linkedIdentity->setRelation('user', $user);
    }

    /**
     * The lower-cased email claim, checked against `email_verified` (OIDC Core
     * 5.1).
     *
     * @throws LoginRefusedException
     */
    private function verifiedEmail(AuthenticatedIdentityData $identity): string
    {
        $email = $identity->claim('email');

        if (! is_string($email) || filter_var(trim($email), FILTER_VALIDATE_EMAIL) === false) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::EmailMissing);
        }

        if ($this->isVerifiedEmailRequired && $this->emailVerifiedClaim($identity) !== true) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::EmailNotVerified);
        }

        return mb_strtolower(trim($email));
    }

    /**
     * The `email_verified` claim (OIDC Core 5.1) as a boolean, or null when
     * the IdP did not send one. Some IdPs send it as the string "true".
     */
    private function emailVerifiedClaim(AuthenticatedIdentityData $identity): ?bool
    {
        return match ($identity->claim('email_verified')) {
            true, 'true' => true,
            false, 'false' => false,
            default => null,
        };
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
        if ($this->activeColumn !== null && ! $user->getAttribute($this->activeColumn)) {
            throw new LoginRefusedException(LoginRefusalReasonEnum::InactiveUser);
        }
    }
}
