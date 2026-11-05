<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support;

use RuntimeException;

/**
 * A user with the three HasRoles methods the Spatie synchronization calls,
 * backed by an in-memory list. `ghost` behaves like a role missing in the app.
 */
class UserWithRoles extends User
{
    /**
     * @var list<string>
     */
    public array $roleNames = [];

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roleNames, true);
    }

    public function assignRole(string $role): static
    {
        if ($role === 'ghost') {
            throw new RuntimeException('There is no role named `ghost`.');
        }

        $this->roleNames[] = $role;

        return $this;
    }

    public function removeRole(string $role): static
    {
        $this->roleNames = array_values(array_diff($this->roleNames, [$role]));

        return $this;
    }
}
