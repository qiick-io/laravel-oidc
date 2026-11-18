<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Qiick\Oidc\Contracts\RoleSynchronizationContract;

/**
 * Records what the role mapping asked for, instead of touching a role table.
 */
final class RecordingRoleSynchronization implements RoleSynchronizationContract
{
    /**
     * @var list<array{granted: list<string>, managed: list<string>}>
     */
    public array $calls = [];

    public function synchronize(Model&Authenticatable $user, array $grantedRoles, array $managedRoles): void
    {
        sort($grantedRoles);
        sort($managedRoles);
        $this->calls[] = ['granted' => $grantedRoles, 'managed' => $managedRoles];
    }
}
