<?php

declare(strict_types=1);

namespace Qiick\Oidc\Erasure;

use LogicException;

/**
 * OIDC identities are shared across the local user's organisations.
 *
 * @api
 */
final class OrganisationScopeUnsupportedException extends LogicException {}
