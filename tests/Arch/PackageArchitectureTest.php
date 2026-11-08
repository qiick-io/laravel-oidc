<?php

declare(strict_types=1);

/**
 * Package-only architecture rules. Naming, suffixes, strict types and readonly
 * DTOs are the shared qiick rules in NamingArchitectureTest.php (configured in
 * naming-architecture.php).
 */
arch('the Laravel namespace only holds the service provider')
    ->expect('Qiick\Oidc\Laravel')
    ->toHaveSuffix('ServiceProvider');

arch('enums are enums')
    ->expect('Qiick\Oidc\Enums')
    ->toBeEnums();

arch('exceptions share one base class')
    ->expect('Qiick\Oidc\Exceptions')
    ->toExtend('Qiick\Oidc\Exceptions\OidcException')
    ->ignoring('Qiick\Oidc\Exceptions\OidcException');

arch('test doubles shipped for apps start with Fake')
    ->expect('Qiick\Oidc\Testing')
    ->toHavePrefix('Fake');

arch('only the test doubles use the Http facade directly')
    ->expect('Illuminate\Support\Facades\Http')
    ->toOnlyBeUsedIn('Qiick\Oidc\Testing');

arch('events are readonly')
    ->expect('Qiick\Oidc\Events')
    ->toBeReadonly();
