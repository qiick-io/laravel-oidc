<?php

declare(strict_types=1);

arch('uses strict types')
    ->expect('Qiick\Oidc')
    ->toUseStrictTypes();

arch('does not call debug functions or env')
    ->expect('Qiick\Oidc')
    ->not->toUse(['dd', 'dump', 'var_dump', 'env', 'ray']);

arch('the Laravel namespace only holds the service provider')
    ->expect('Qiick\Oidc\Laravel')
    ->toHaveSuffix('ServiceProvider');

arch('data objects are readonly and suffixed')
    ->expect('Qiick\Oidc\Data')
    ->toBeReadonly()
    ->toHaveSuffix('Data');

arch('enums use the enum suffix')
    ->expect('Qiick\Oidc\Enums')
    ->toBeEnums()
    ->toHaveSuffix('Enum');

arch('contracts are interfaces')
    ->expect('Qiick\Oidc\Contracts')
    ->toBeInterfaces()
    ->toHaveSuffix('Contract');

arch('repositories use the repository suffix')
    ->expect('Qiick\Oidc\Repositories')
    ->toHaveSuffix('Repository');

arch('services use the service suffix')
    ->expect('Qiick\Oidc\Services')
    ->toHaveSuffix('Service');

arch('exceptions use the exception suffix and share one base class')
    ->expect('Qiick\Oidc\Exceptions')
    ->toHaveSuffix('Exception')
    ->toExtend('Qiick\Oidc\Exceptions\OidcException')
    ->ignoring('Qiick\Oidc\Exceptions\OidcException');

arch('test doubles shipped for apps start with Fake')
    ->expect('Qiick\Oidc\Testing')
    ->toHavePrefix('Fake');

arch('only the test doubles use the Http facade directly')
    ->expect('Illuminate\Support\Facades\Http')
    ->toOnlyBeUsedIn('Qiick\Oidc\Testing');

arch('controllers are thin and suffixed')
    ->expect('Qiick\Oidc\Http\Controllers')
    ->toHaveSuffix('Controller')
    ->not->toUse('Illuminate\Support\Facades\DB');

arch('middleware use the middleware suffix')
    ->expect('Qiick\Oidc\Http\Middleware')
    ->toHaveSuffix('Middleware');

arch('models use bare domain nouns')
    ->expect('Qiick\Oidc\Models')
    ->classes()
    ->not->toHaveSuffix('Model');

arch('events use the event suffix and are readonly')
    ->expect('Qiick\Oidc\Events')
    ->toHaveSuffix('Event')
    ->toBeReadonly();

arch('listeners use the listener suffix')
    ->expect('Qiick\Oidc\Listeners')
    ->toHaveSuffix('Listener');

arch('console commands use the command suffix')
    ->expect('Qiick\Oidc\Console')
    ->toHaveSuffix('Command');
