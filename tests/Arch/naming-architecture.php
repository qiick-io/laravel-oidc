<?php

declare(strict_types=1);

/**
 * This repo's settings for the shared `NamingArchitectureTest.php` (qiick standards).
 *
 * Written once by the sync, never overwritten or checked: it is this repo's own.
 * Package-only rules (one exception base class, Fake test doubles, the Laravel
 * namespace) are in `PackageArchitectureTest.php`.
 */
return [
    'namespace' => 'Qiick\Oidc',

    'ignoring' => [],

    // Roles of this package beyond the shared table.
    'suffixes' => [
        'Console' => 'Command',
        'Repositories' => 'Repository',
        'Factories' => 'Factory',
    ],
];
