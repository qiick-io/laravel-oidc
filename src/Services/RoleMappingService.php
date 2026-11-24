<?php

declare(strict_types=1);

namespace Qiick\Oidc\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Qiick\Oidc\Contracts\RoleSynchronizationContract;
use Qiick\Oidc\Data\AuthenticatedIdentityData;

/**
 * Maps the IdP's roles to app roles at every SSO login (design section 4,
 * "Role mapping").
 *
 * Guarantees, whatever the IdP sends:
 * - only app roles that appear as values of the map are ever granted or
 *   revoked (the allowlist); local roles outside it are never touched;
 * - `super-admin` and the configured forbidden roles are never granted, even
 *   when mapped, and never revoked, so the break-glass admin stays local;
 * - without the claim in the login, nothing changes.
 *
 * The claim is either a flat list of role names, or (with `organization`)
 * Signaculum's `orgs` list, of which only the configured organisation counts.
 * A login without that organisation in `orgs` revokes the managed roles: the
 * user is no longer a member.
 *
 * @internal Not part of the public API (docs/PUBLIC-API.md); it can change in any release.
 */
final readonly class RoleMappingService
{
    public const array ALWAYS_FORBIDDEN_ROLES = ['super-admin'];

    /**
     * @param  array<string, list<string>>  $roleMap  IdP role => app roles
     * @param  list<string>  $forbiddenRoles
     */
    public function __construct(
        private RoleSynchronizationContract $roleSynchronization,
        private bool $isEnabled,
        private string $claimPath,
        private ?string $organization,
        private array $roleMap,
        private array $forbiddenRoles,
    ) {}

    /**
     * @return list<string>|null the granted app roles, or null when nothing changed
     */
    public function apply(Model&Authenticatable $user, AuthenticatedIdentityData $identity): ?array
    {
        if (! $this->isEnabled || $this->roleMap === []) {
            return null;
        }

        $identityProviderRoles = $this->identityProviderRoles($identity->claims);

        if ($identityProviderRoles === null) {
            return null;
        }

        $managedRoles = $this->managedRoles();
        $grantedRoles = [];

        foreach ($identityProviderRoles as $identityProviderRole) {
            foreach ($this->roleMap[$identityProviderRole] ?? [] as $appRole) {
                if (in_array($appRole, $managedRoles, true)) {
                    $grantedRoles[] = $appRole;
                }
            }
        }

        $grantedRoles = array_values(array_unique($grantedRoles));
        $this->roleSynchronization->synchronize($user, $grantedRoles, $managedRoles);

        return $grantedRoles;
    }

    /**
     * @return list<string>
     */
    private function managedRoles(): array
    {
        $forbiddenRoles = [...self::ALWAYS_FORBIDDEN_ROLES, ...$this->forbiddenRoles];
        $mappedRoles = array_unique(array_merge(...array_values($this->roleMap)));

        return array_values(array_filter($mappedRoles, fn (string $role): bool => ! in_array($role, $forbiddenRoles, true)));
    }

    /**
     * The IdP role names in the login, or null when the claim is absent or
     * not the expected shape (then local roles stay as they are).
     *
     * @param  array<string, mixed>  $claims
     * @return list<string>|null
     */
    private function identityProviderRoles(array $claims): ?array
    {
        $claim = data_get($claims, $this->claimPath);

        if (! is_array($claim)) {
            return null;
        }

        if ($this->organization === null) {
            return $this->stringList($claim);
        }

        foreach ($claim as $organizationMembership) {
            $isThisOrganization = is_array($organizationMembership)
                && (($organizationMembership['id'] ?? null) === $this->organization || ($organizationMembership['slug'] ?? null) === $this->organization);

            if ($isThisOrganization) {
                return is_array($organizationMembership['roles'] ?? null) ? $this->stringList($organizationMembership['roles']) : [];
            }
        }

        return [];
    }

    /**
     * Role names from a flat list (`["admin","member"]`) or from a map whose
     * keys are the role names (Zitadel's `urn:zitadel:iam:org:project:roles`
     * claim: `{"member":{"<orgId>":"<domain>"}}`).
     *
     * @param  array<array-key, mixed>  $values
     * @return list<string>
     */
    private function stringList(array $values): array
    {
        $roleNames = array_values(array_filter($values, is_string(...)));

        if ($roleNames !== []) {
            return $roleNames;
        }

        foreach ($values as $key => $value) {
            if (is_string($key) && $key !== '' && is_array($value)) {
                $roleNames[] = $key;
            }
        }

        return $roleNames;
    }
}
