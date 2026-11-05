<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Qiick\Oidc\Data\AuthenticatedIdentityData;

/**
 * Decides whether the IdP says MFA happened during this login: an `amr` value
 * (RFC 8176, for example `mfa`, `otp`, `hwk`) in the accepted list, or an `acr`
 * in the accepted list. Both claims come from the signed id_token (userinfo
 * claims never override them).
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
    ) {}

    public function isSatisfied(AuthenticatedIdentityData $identity): bool
    {
        $authenticationMethods = $identity->claim('amr');

        if (is_array($authenticationMethods) && array_intersect($this->acceptedAmrValues, array_filter($authenticationMethods, is_string(...))) !== []) {
            return true;
        }

        $authenticationContext = $identity->claim('acr');

        return is_string($authenticationContext) && in_array($authenticationContext, $this->acceptedAcrValues, true);
    }
}
