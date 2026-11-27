<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Qiick\Oidc\Data\AuthenticatedIdentityData;

/**
 * Decides whether a trusted IdP proved MFA during this login: a signed
 * `amr` value (RFC 8176) or `acr` in the app's accepted lists.
 *
 * When the login asked for an `acr` and the IdP did not return one of the
 * requested values, MFA is not proven at all, whatever `amr` says: the IdP
 * did not confirm the step-up, so the app's own second factor runs.
 *
 * @internal Not part of the public API (docs/PUBLIC-API.md); it can change in any release.
 */
final readonly class MultiFactorClaimService
{
    /**
     * @param  list<string>  $acceptedAmrValues
     * @param  list<string>  $acceptedAcrValues
     */
    public function __construct(
        private array $acceptedAmrValues,
        private array $acceptedAcrValues,
        private bool $isProviderTrusted,
    ) {}

    public function isSatisfied(AuthenticatedIdentityData $identity): bool
    {
        if (! $this->isProviderTrusted || ! $identity->isRequestedAuthenticationContextMet) {
            return false;
        }

        $authenticationMethods = $identity->claim('amr');

        if (is_array($authenticationMethods) && array_intersect($this->acceptedAmrValues, array_filter($authenticationMethods, is_string(...))) !== []) {
            return true;
        }

        $authenticationContext = $identity->claim('acr');

        return is_string($authenticationContext) && in_array($authenticationContext, $this->acceptedAcrValues, true);
    }
}
