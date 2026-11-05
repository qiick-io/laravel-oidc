<?php

declare(strict_types=1);

arch('uses strict types')
    ->expect('Qiick\Oidc')
    ->toUseStrictTypes();

arch('does not call debug functions or env')
    ->expect('Qiick\Oidc')
    ->not->toUse(['dd', 'dump', 'var_dump', 'env', 'ray']);

arch('the service provider is the only class in the Laravel namespace')
    ->expect('Qiick\Oidc\Laravel')
    ->toHaveSuffix('ServiceProvider');
