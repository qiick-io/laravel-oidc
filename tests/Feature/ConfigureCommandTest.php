<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Contracts\SecondFactorChallengeContract;
use Qiick\Oidc\Services\FortifySecondFactorChallengeService;
use Qiick\Oidc\Testing\FakeIdentityProvider;
use Qiick\Oidc\Tests\Support\Fortify\FakeFortify;
use Qiick\Oidc\Tests\Support\Fortify\FakeTwoFactorAuthenticatable;
use Qiick\Oidc\Tests\Support\Fortify\UserWithTwoFactor;
use Qiick\Oidc\Tests\Support\UserWithRoles;

/**
 * Runs `oidc:configure --json` and returns the exit code and the report.
 *
 * @param  array<string, mixed>  $options
 * @return array{0: int, 1: array<string, mixed>, 2: string}
 */
function configureOidc(array $options = []): array
{
    $exitCode = Artisan::call('oidc:configure', ['--json' => true, ...$options]);
    $output = Artisan::output();

    return [$exitCode, json_decode($output, true, 512, JSON_THROW_ON_ERROR), $output];
}

/**
 * @param  array<string, mixed>  $report
 * @return array<string, string>
 */
function statusesByCheck(array $report): array
{
    return array_column($report['checks'], 'status', 'check');
}

beforeEach(function (): void {
    $this->environmentDirectory = sys_get_temp_dir().'/oidc-configure-'.bin2hex(random_bytes(4));
    mkdir($this->environmentDirectory);
    app()->useEnvironmentPath($this->environmentDirectory);
});

afterEach(function (): void {
    @unlink($this->environmentDirectory.'/.env');
    @rmdir($this->environmentDirectory);
});

it('passes for a working IdP and lists the URIs to register', function (): void {
    FakeIdentityProvider::fake();

    [$exitCode, $report, $output] = configureOidc();

    expect($exitCode)->toBe(0)
        ->and($report['ok'])->toBeTrue()
        ->and(statusesByCheck($report))->toBe([
            'settings' => 'ok',
            'discovery' => 'ok',
            'end session' => 'ok',
            'algorithms' => 'ok',
            'signing keys' => 'ok',
            'back-channel logout' => 'ok',
            'client' => 'ok',
            'redirect uri' => 'ok',
            'timezone' => 'ok',
            'cache store' => 'warning',
        ])
        ->and($report['register_at_identity_provider'])->toBe([
            'redirect_uri' => 'http://localhost/auth/oidc/callback',
            'post_logout_redirect_uri' => 'http://localhost/auth/oidc/logged-out',
            'backchannel_logout_uri' => 'http://localhost/auth/oidc/backchannel-logout',
        ])
        ->and($output)->not->toContain('fake-client-secret');
});

it('takes the settings from the options, even while SSO is off', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    Config::set(['oidc.enabled' => false, 'oidc.issuer' => null, 'oidc.client_id' => null, 'oidc.client_secret' => null]);

    [$exitCode, $report] = configureOidc(['--issuer' => $identityProvider->issuer, '--client-id' => 'laravel-app']);

    expect($exitCode)->toBe(0)->and(statusesByCheck($report)['client'])->toBe('warning');
});

it('fails without issuer and client id', function (): void {
    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe(1)->and(statusesByCheck($report))->toBe(['settings' => 'failure']);
});

it('fails the deploy check for allowed IdP claims while trust is off', function (string $key, string $value): void {
    FakeIdentityProvider::fake(configOverrides: [$key => [$value]]);

    $this->artisan('oidc:check')->expectsOutputToContain('oidc.mfa.trust_provider')->assertExitCode(1);
})->with([
    'amr' => ['mfa.amr_values', 'mfa'],
    'acr' => ['mfa.acr_values', 'urn:qiick:loa:mfa'],
]);

it('reports when required MFA has no usable provider or local challenge', function (): void {
    FakeIdentityProvider::fake(configOverrides: ['mfa.required' => true]);

    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe(1)
        ->and(statusesByCheck($report)['local MFA'])->toBe('failure');
});

it('requires the configured user model to support Fortify even when its route exists', function (): void {
    FakeIdentityProvider::fake(configOverrides: ['mfa.required' => true]);
    Route::get('/two-factor-challenge', fn () => 'challenge')->name('two-factor.login');
    Route::getRoutes()->refreshNameLookups();
    app()->instance(SecondFactorChallengeContract::class, new FortifySecondFactorChallengeService(
        true,
        FakeFortify::class,
        FakeTwoFactorAuthenticatable::class,
    ));

    $this->artisan('oidc:check')->expectsOutputToContain('no trusted IdP claims or usable local Fortify enrollment')->assertExitCode(1);
});

it('passes the deploy check with explicit Signaculum MFA trust', function (): void {
    FakeIdentityProvider::fake(configOverrides: [
        'mfa.required' => true,
        'mfa.trust_provider' => true,
        'mfa.amr_values' => ['mfa'],
        'mfa.acr_values' => ['urn:qiick:loa:mfa'],
    ]);

    $this->artisan('oidc:check')->assertExitCode(0);
});

it('checks whether a required local Fortify challenge has an enrolled user', function (?string $secret, bool $isConfirmed, ?string $activeColumn, int $exitCode): void {
    FakeIdentityProvider::fake(configOverrides: [
        'mfa.required' => true,
        'users.model' => UserWithTwoFactor::class,
        'users.active_column' => $activeColumn,
    ]);
    Schema::table('users', function (Blueprint $table): void {
        $table->text('two_factor_secret')->nullable();
        $table->timestamp('two_factor_confirmed_at')->nullable();
    });
    Route::get('/two-factor-challenge', fn () => 'challenge')->name('two-factor.login');
    Route::getRoutes()->refreshNameLookups();
    FakeFortify::$isConfirmationRequired = true;
    app()->instance(SecondFactorChallengeContract::class, new FortifySecondFactorChallengeService(
        true,
        FakeFortify::class,
        FakeTwoFactorAuthenticatable::class,
    ));
    localUser(attributes: [
        'two_factor_secret' => $secret,
        'two_factor_confirmed_at' => $isConfirmed ? Date::now() : null,
    ]);

    $this->artisan('oidc:check')->assertExitCode($exitCode);
})->with([
    'enrolled' => ['totp-secret', true, null, 0],
    'no enrollment' => [null, false, null, 1],
    'unconfirmed enrollment' => ['totp-secret', false, null, 1],
    'only an inactive user is enrolled' => ['totp-secret', true, 'email_verified_at', 1],
]);

it('checks an enabled installation with incomplete provider settings', function (): void {
    Config::set('oidc.enabled', true);

    $this->artisan('oidc:check')->expectsOutputToContain('Issuer and client id are required')->assertExitCode(1);
});

it('passes the deploy check while OIDC is disabled', function (): void {
    Http::fake();

    $this->artisan('oidc:check')->expectsOutput('OIDC is disabled.')->assertExitCode(0);

    Http::assertNothingSent();
});

it('checks the provider when the application enables OIDC through its own repository', function (): void {
    FakeIdentityProvider::fake(configOverrides: ['mfa.amr_values' => ['mfa']]);
    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();
    Config::set('oidc.enabled', false);
    $repository = Mockery::mock(ProviderConfigurationRepositoryContract::class);
    $repository->shouldReceive('isEnabled')->andReturnTrue();
    $repository->shouldReceive('configuration')->andReturn($configuration);
    app()->instance(ProviderConfigurationRepositoryContract::class, $repository);

    $this->artisan('oidc:check')->expectsOutputToContain('oidc.mfa.trust_provider')->assertExitCode(1);
});

it('leaves custom second-factor enrollment to the application', function (): void {
    FakeIdentityProvider::fake(configOverrides: ['mfa.required' => true]);
    app()->instance(SecondFactorChallengeContract::class, Mockery::mock(SecondFactorChallengeContract::class));

    $this->artisan('oidc:check')->assertExitCode(0);
});

it('fails on a discovery problem and on algorithms the package cannot accept', function (array $discoveryOverrides, string $failedCheck): void {
    FakeIdentityProvider::fake()->withDiscovery($discoveryOverrides);

    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe(1)->and(statusesByCheck($report)[$failedCheck])->toBe('failure');
})->with([
    'issuer mismatch' => [['issuer' => 'https://idp.example.com/realms/other'], 'discovery'],
    'no PKCE S256' => [['code_challenge_methods_supported' => ['plain']], 'discovery'],
    'HS256 only' => [['id_token_signing_alg_values_supported' => ['HS256']], 'algorithms'],
]);

it('warns when the IdP has no end session endpoint', function (): void {
    FakeIdentityProvider::fake()->withDiscovery(['end_session_endpoint' => null]);

    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe(0)->and(statusesByCheck($report)['end session'])->toBe('warning');
});

it('fails on the per-request array cache outside tests, where no login could complete', function (): void {
    FakeIdentityProvider::fake();
    Config::set('oidc.cache.store', 'array');
    app()->detectEnvironment(fn (): string => 'production');

    [$exitCode, $report] = configureOidc();
    $cacheCheck = collect($report['checks'])->firstWhere('check', 'cache store');

    expect($exitCode)->toBe(1)
        ->and($cacheCheck['status'])->toBe('failure')
        ->and($cacheCheck['detail'])->toContain('array');
});

it('names the cache store that makes each login state single-use', function (): void {
    FakeIdentityProvider::fake();
    Config::set('oidc.cache.store', 'database');
    // Touch the database first: its lazy migration would reset the Artisan output buffer mid-command.
    Cache::store('database')->get('warm-up');

    [, $report] = configureOidc();

    expect(collect($report['checks'])->firstWhere('check', 'cache store'))->toBe([
        'check' => 'cache store',
        'status' => 'ok',
        'detail' => 'Cache store [database]: each login state is consumed there once. With several app servers, use a store they share (database, redis).',
    ]);
});

it('checks the app default cache store when oidc.cache.store is empty, and accepts a shared one outside tests', function (): void {
    FakeIdentityProvider::fake();
    Config::set('oidc.cache.store', '');
    Config::set('cache.default', 'database');
    Cache::store('database')->get('warm-up');
    app()->detectEnvironment(fn (): string => 'production');

    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe(0)
        ->and(collect($report['checks'])->firstWhere('check', 'cache store')['detail'])->toStartWith('Cache store [database]:');
});

it('warns that a file cache store is per server', function (): void {
    FakeIdentityProvider::fake();
    Config::set('oidc.cache.store', 'file');
    // The file store outlives the test process: drop what an earlier run cached.
    Cache::store('file')->flush();

    [$exitCode, $report] = configureOidc();
    $cacheCheck = collect($report['checks'])->firstWhere('check', 'cache store');

    expect($exitCode)->toBe(0)
        ->and($cacheCheck['status'])->toBe('warning')
        ->and($cacheCheck['detail'])->toContain('file driver');
});

it('warns when app.timezone is not UTC', function (): void {
    FakeIdentityProvider::fake();
    Config::set('app.timezone', 'Europe/Rome');

    [$exitCode, $report] = configureOidc();
    $timezoneCheck = collect($report['checks'])->firstWhere('check', 'timezone');

    expect($exitCode)->toBe(0)
        ->and($timezoneCheck['status'])->toBe('warning')
        ->and($timezoneCheck['detail'])->toBe('app.timezone is Europe/Rome; the package expects UTC in its timestamp columns, so set it to UTC.');
});

it('fails in SSO-only mode without a break-glass account', function (bool $hasBreakGlassAccount): void {
    Schema::table('users', function (Blueprint $table): void {
        $table->text('two_factor_secret')->nullable();
        $table->timestamp('two_factor_confirmed_at')->nullable();
    });
    Config::set('auth.providers.users.model', UserWithRoles::class);
    FakeIdentityProvider::fake(configOverrides: ['only' => true]);
    UserWithRoles::$rolesByEmail = ['owner@example.com' => $hasBreakGlassAccount ? ['super-admin'] : ['admin']];
    UserWithRoles::query()->forceCreate([
        'name' => 'Owner', 'email' => 'owner@example.com', 'password' => 'x',
        'two_factor_secret' => 'secret', 'two_factor_confirmed_at' => Date::now(),
    ]);

    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe($hasBreakGlassAccount ? 0 : 1)
        ->and(statusesByCheck($report)['break-glass'])->toBe($hasBreakGlassAccount ? 'ok' : 'failure');
})->with(['with break-glass' => true, 'without' => false]);

it('writes the settings to .env when every check passes, keeping the other lines', function (): void {
    $identityProvider = FakeIdentityProvider::fake(clientSecret: 'se cret"${x}');
    file_put_contents($this->environmentDirectory.'/.env', "APP_NAME=Externa\nOIDC_ISSUER=https://old.example.com\n");

    [$exitCode] = configureOidc(['--write-env' => true]);

    expect($exitCode)->toBe(0)
        ->and(file_get_contents($this->environmentDirectory.'/.env'))->toBe(
            "APP_NAME=Externa\nOIDC_ISSUER={$identityProvider->issuer}\nOIDC_ENABLED=true\nOIDC_CLIENT_ID=laravel-app\nOIDC_CLIENT_SECRET='se cret\"\${x}'\n"
        );
});

it('creates .env for a public client and reports where it wrote', function (): void {
    $identityProvider = FakeIdentityProvider::fake(clientSecret: null);
    $environmentPath = $this->environmentDirectory.'/.env';

    [$exitCode, $report] = configureOidc(['--write-env' => true]);

    expect($exitCode)->toBe(0)
        ->and(file_get_contents($environmentPath))->toBe(
            "OIDC_ENABLED=true\nOIDC_ISSUER={$identityProvider->issuer}\nOIDC_CLIENT_ID=laravel-app\nOIDC_CLIENT_SECRET=\n"
        )
        ->and(collect($report['checks'])->firstWhere('check', 'env'))->toBe([
            'check' => 'env',
            'status' => 'ok',
            'detail' => "Wrote OIDC_ENABLED, OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET to {$environmentPath}.",
        ]);
});

it('replaces an existing line with a value holding a backslash or a dollar sign literally', function (): void {
    FakeIdentityProvider::fake(clientSecret: 'a\\1$1b');
    file_put_contents($this->environmentDirectory.'/.env', "OIDC_CLIENT_SECRET=old\nAPP_NAME=Externa");

    configureOidc(['--write-env' => true]);

    expect(file_get_contents($this->environmentDirectory.'/.env'))->toStartWith("OIDC_CLIENT_SECRET='a\\1\$1b'\nAPP_NAME=Externa\n");
});

it('refuses to write a secret that cannot be quoted safely', function (): void {
    FakeIdentityProvider::fake(clientSecret: "it's");
    file_put_contents($this->environmentDirectory.'/.env', "APP_NAME=Externa\n");

    [$exitCode, $report] = configureOidc(['--write-env' => true]);

    expect($exitCode)->toBe(1)
        ->and(statusesByCheck($report)['env'])->toBe('failure')
        ->and(file_get_contents($this->environmentDirectory.'/.env'))->toBe("APP_NAME=Externa\n");
});

it('writes nothing when a check fails', function (): void {
    FakeIdentityProvider::fake()->withDiscovery(['issuer' => 'https://evil.example.com']);
    file_put_contents($this->environmentDirectory.'/.env', "APP_NAME=Externa\n");

    configureOidc(['--write-env' => true]);

    expect(file_get_contents($this->environmentDirectory.'/.env'))->toBe("APP_NAME=Externa\n");
});

it('prints a readable table without --json', function (): void {
    FakeIdentityProvider::fake();

    $this->artisan('oidc:configure')
        ->expectsOutputToContain('Register at the IdP:')
        ->expectsOutputToContain('The OIDC setup looks good.')
        ->assertSuccessful();
});

it('reports the detail of every check for a working IdP', function (): void {
    FakeIdentityProvider::fake();

    [, $report] = configureOidc();

    expect($report['checks'])->toBe([
        ['check' => 'settings', 'status' => 'ok', 'detail' => 'Issuer https://idp.example.com/realms/test, client laravel-app.'],
        ['check' => 'discovery', 'status' => 'ok', 'detail' => 'Issuer matches; authorization code flow with PKCE S256 is available.'],
        ['check' => 'end session', 'status' => 'ok', 'detail' => 'RP-initiated logout is available.'],
        ['check' => 'algorithms', 'status' => 'ok', 'detail' => 'id_token signed with RS256.'],
        ['check' => 'signing keys', 'status' => 'ok', 'detail' => '1 signing key(s) in the JWKS.'],
        ['check' => 'back-channel logout', 'status' => 'ok', 'detail' => 'The IdP sends back-channel logout tokens with sid.'],
        ['check' => 'client', 'status' => 'ok', 'detail' => 'Confidential client (client_secret_basic).'],
        ['check' => 'redirect uri', 'status' => 'ok', 'detail' => 'http://localhost/auth/oidc/callback'],
        ['check' => 'timezone', 'status' => 'ok', 'detail' => 'app.timezone is UTC.'],
        ['check' => 'cache store', 'status' => 'warning', 'detail' => 'Cache store [array] uses the array driver, accepted only because APP_ENV is testing. Any deployed app needs a shared store (database, redis).'],
    ]);
});

it('explains a missing end session endpoint and a public client', function (): void {
    FakeIdentityProvider::fake(clientSecret: null)->withDiscovery(['end_session_endpoint' => null]);

    [, $report] = configureOidc();
    $detailsByCheck = array_column($report['checks'], 'detail', 'check');

    expect($detailsByCheck['end session'])->toBe('The IdP has no end_session_endpoint: logout ends the local session only.')
        ->and($detailsByCheck['client'])->toBe('No client secret: the IdP client must be public (PKCE only).');
});

it('names the algorithms on both sides when none is shared', function (): void {
    Config::set('oidc.id_token.algorithms', ['HS256', 'RS384', 'RS256']);
    FakeIdentityProvider::fake()->withDiscovery(['id_token_signing_alg_values_supported' => ['ES256', 'PS384']]);

    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe(1)
        ->and(array_column($report['checks'], 'detail', 'check')['algorithms'])
        ->toBe('The IdP signs id_tokens with ES256, PS384; oidc.id_token.algorithms allows RS256, RS384.');
});

it('lists only the shared algorithms', function (): void {
    Config::set('oidc.id_token.algorithms', ['RS256', 'RS384']);
    FakeIdentityProvider::fake()->withDiscovery(['id_token_signing_alg_values_supported' => ['ES256', 'RS384', 'RS256']]);

    [, $report] = configureOidc();

    expect(array_column($report['checks'], 'detail', 'check')['algorithms'])->toBe('id_token signed with RS256, RS384.');
});

it('fails when the JWKS cannot be fetched', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    $identityProvider->withDiscovery(['jwks_uri' => $identityProvider->issuer.'/missing-jwks']);

    [$exitCode, $report] = configureOidc();
    $signingKeysCheck = collect($report['checks'])->firstWhere('check', 'signing keys');

    expect($exitCode)->toBe(1)
        ->and($signingKeysCheck['status'])->toBe('failure')
        ->and($signingKeysCheck['detail'])->toContain('HTTP 404');
});

it('counts only RSA and EC signing keys in the JWKS', function (mixed $publishedKeys, string $status, string $detail): void {
    Http::fake(['https://idp.example.com/realms/test/custom-jwks' => Http::response(['keys' => $publishedKeys])]);
    $identityProvider = FakeIdentityProvider::fake();
    $identityProvider->withDiscovery(['jwks_uri' => $identityProvider->issuer.'/custom-jwks']);

    [, $report] = configureOidc();
    $signingKeysCheck = collect($report['checks'])->firstWhere('check', 'signing keys');

    expect([$signingKeysCheck['status'], $signingKeysCheck['detail']])->toBe([$status, $detail]);
})->with([
    'signing keys only' => [[
        ['kty' => 'RSA', 'use' => 'sig'],
        ['kty' => 'EC'],
        ['kty' => 'RSA', 'use' => 'enc'],
        ['kty' => 'oct', 'use' => 'sig'],
        ['use' => 'sig'],
        'not-a-key',
    ], 'ok', '2 signing key(s) in the JWKS.'],
    'none usable' => [[['kty' => 'RSA', 'use' => 'enc']], 'failure', 'The JWKS has no RSA or EC signing key.'],
    'keys not a list' => ['not-a-list', 'failure', 'The JWKS has no RSA or EC signing key.'],
]);

it('judges the redirect URI', function (string $redirectUri, string $status, string $detail): void {
    FakeIdentityProvider::fake(configOverrides: ['redirect_uri' => $redirectUri]);

    [, $report] = configureOidc();
    $redirectChecks = collect($report['checks'])->where('check', 'redirect uri')->values()->all();

    expect($redirectChecks)->toBe([['check' => 'redirect uri', 'status' => $status, 'detail' => $detail]]);
})->with([
    'https' => ['https://app.example.com/cb', 'ok', 'https://app.example.com/cb'],
    'http on localhost' => ['http://localhost/cb', 'ok', 'http://localhost/cb'],
    'http on 127.0.0.1' => ['http://127.0.0.1/cb', 'ok', 'http://127.0.0.1/cb'],
    'http on [::1]' => ['http://[::1]/cb', 'ok', 'http://[::1]/cb'],
    'http on a .test host' => ['http://app.test/cb', 'ok', 'http://app.test/cb'],
    'http on a host that starts with .test' => ['http://test.example.com/cb', 'warning', '[http://test.example.com/cb] uses plain http outside localhost; most IdPs refuse it.'],
    'http on a public host' => ['http://app.example.com/cb', 'warning', '[http://app.example.com/cb] uses plain http outside localhost; most IdPs refuse it.'],
    'not absolute' => ['/cb', 'failure', '[/cb] is not an absolute URL. Set APP_URL or oidc.redirect_uri.'],
    'other scheme' => ['ftp://app.example.com/cb', 'failure', '[ftp://app.example.com/cb] is not an absolute URL. Set APP_URL or oidc.redirect_uri.'],
]);

it('takes the client secret from its option and ignores empty options', function (): void {
    FakeIdentityProvider::fake(clientSecret: null);

    [, $report] = configureOidc(['--client-secret' => 'from-the-option', '--issuer' => '']);
    $detailsByCheck = array_column($report['checks'], 'detail', 'check');

    expect($detailsByCheck['client'])->toBe('Confidential client (client_secret_basic).')
        ->and($detailsByCheck['settings'])->toBe('Issuer https://idp.example.com/realms/test, client laravel-app.');
});

it('reads the discovery document fresh instead of the cached one', function (): void {
    $identityProvider = FakeIdentityProvider::fake();
    configureOidc();
    $identityProvider->withDiscovery(['end_session_endpoint' => null]);

    [, $report] = configureOidc();

    expect(statusesByCheck($report)['end session'])->toBe('warning');
});

it('leaves out the back-channel URI when the app has no such route', function (): void {
    FakeIdentityProvider::fake(configOverrides: ['redirect_uri' => 'https://app.example.com/cb']);
    Route::setRoutes(new RouteCollection);

    [, $report] = configureOidc();

    expect($report['register_at_identity_provider'])->toBe([
        'redirect_uri' => 'https://app.example.com/cb',
        'post_logout_redirect_uri' => 'http://localhost',
    ]);
});

it('names the configured break-glass roles when no account qualifies', function (): void {
    Config::set('auth.providers.users.model', UserWithRoles::class);
    FakeIdentityProvider::fake(configOverrides: ['only' => true, 'break_glass.roles' => ['super-admin', 42, 'owner']]);
    UserWithRoles::$rolesByEmail = ['owner@example.com' => ['admin']];
    UserWithRoles::query()->forceCreate(['name' => 'Owner', 'email' => 'owner@example.com', 'password' => 'x']);

    [, $report] = configureOidc();

    expect(array_column($report['checks'], 'detail', 'check')['break-glass'])
        ->toBe('OIDC_ONLY is on but no account qualifies as break-glass (super-admin, owner with a confirmed second factor).');
});

it('prints the JSON report pretty and with unescaped slashes', function (): void {
    FakeIdentityProvider::fake();

    [, , $output] = configureOidc();

    expect($output)->toContain("{\n    \"ok\": true,")
        ->and($output)->toContain('"redirect_uri": "http://localhost/auth/oidc/callback"');
});

it('prints every check and the URIs to register in the table', function (): void {
    FakeIdentityProvider::fake(clientSecret: null);

    $this->artisan('oidc:configure')
        ->expectsTable(['Check', 'Status', 'Detail'], [
            ['settings', 'OK', 'Issuer https://idp.example.com/realms/test, client laravel-app.'],
            ['discovery', 'OK', 'Issuer matches; authorization code flow with PKCE S256 is available.'],
            ['end session', 'OK', 'RP-initiated logout is available.'],
            ['algorithms', 'OK', 'id_token signed with RS256.'],
            ['signing keys', 'OK', '1 signing key(s) in the JWKS.'],
            ['back-channel logout', 'OK', 'The IdP sends back-channel logout tokens with sid.'],
            ['client', 'WARNING', 'No client secret: the IdP client must be public (PKCE only).'],
            ['redirect uri', 'OK', 'http://localhost/auth/oidc/callback'],
            ['timezone', 'OK', 'app.timezone is UTC.'],
            ['cache store', 'WARNING', 'Cache store [array] uses the array driver, accepted only because APP_ENV is testing. Any deployed app needs a shared store (database, redis).'],
        ])
        ->expectsOutput('Register at the IdP:')
        ->expectsOutput('  redirect_uri: http://localhost/auth/oidc/callback')
        ->expectsOutput('  post_logout_redirect_uri: http://localhost/auth/oidc/logged-out')
        ->expectsOutput('  backchannel_logout_uri: http://localhost/auth/oidc/backchannel-logout')
        ->expectsOutput('The OIDC setup looks good.')
        ->assertSuccessful();
});

it('prints the failure line and no URIs without settings', function (): void {
    $this->artisan('oidc:configure')
        ->expectsOutput('The OIDC setup has failures.')
        ->doesntExpectOutput('Register at the IdP:')
        ->assertFailed();
});

it('lists the front-channel logout URI and how to register it when front-channel logout is on', function (): void {
    FakeIdentityProvider::fake(configOverrides: ['frontchannel_logout.enabled' => true]);

    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe(0)
        ->and(collect($report['checks'])->firstWhere('check', 'front-channel logout'))->toBe([
            'check' => 'front-channel logout',
            'status' => 'ok',
            'detail' => 'Register http://localhost/auth/oidc/frontchannel-logout as the front-channel logout URI with "front-channel logout session required" (frontchannel_logout_session_required), so the IdP sends iss and sid.',
        ])
        ->and($report['register_at_identity_provider'])->toBe([
            'redirect_uri' => 'http://localhost/auth/oidc/callback',
            'post_logout_redirect_uri' => 'http://localhost/auth/oidc/logged-out',
            'backchannel_logout_uri' => 'http://localhost/auth/oidc/backchannel-logout',
            'frontchannel_logout_uri' => 'http://localhost/auth/oidc/frontchannel-logout',
        ]);
});

it('neither checks nor lists front-channel logout while it is off', function (): void {
    FakeIdentityProvider::fake();

    [, $report] = configureOidc();

    expect(statusesByCheck($report))->not->toHaveKey('front-channel logout')
        ->and($report['register_at_identity_provider'])->not->toHaveKey('frontchannel_logout_uri');
});

it('fails when front-channel logout is on but its route is missing', function (): void {
    FakeIdentityProvider::fake(configOverrides: ['frontchannel_logout.enabled' => true, 'redirect_uri' => 'https://app.example.com/cb']);
    Route::setRoutes(new RouteCollection);

    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe(1)
        ->and(collect($report['checks'])->firstWhere('check', 'front-channel logout'))->toBe([
            'check' => 'front-channel logout',
            'status' => 'failure',
            'detail' => 'oidc.frontchannel_logout.enabled is on but the oidc.frontchannel-logout route is not registered.',
        ])
        ->and($report['register_at_identity_provider'])->not->toHaveKey('frontchannel_logout_uri');
});

it('reports the capabilities the IdP advertises', function (): void {
    FakeIdentityProvider::fake()->withDiscovery([
        'frontchannel_logout_supported' => true,
        'frontchannel_logout_session_supported' => 'true',
        'acr_values_supported' => ['urn:qiick:loa:pwd', 42, 'urn:qiick:loa:mfa'],
        'claims_parameter_supported' => true,
    ]);

    [, $report] = configureOidc();

    expect($report['identity_provider_capabilities'])->toBe([
        'frontchannel_logout_supported' => true,
        'frontchannel_logout_session_supported' => false,
        'backchannel_logout_supported' => true,
        'backchannel_logout_session_supported' => true,
        'acr_values_supported' => ['urn:qiick:loa:pwd', 'urn:qiick:loa:mfa'],
        'claims_parameter_supported' => true,
    ]);
});

it('reports no capabilities when discovery fails', function (): void {
    FakeIdentityProvider::fake()->withDiscovery(['issuer' => 'https://evil.example.com']);

    [, $report] = configureOidc();

    expect($report['identity_provider_capabilities'])->toBeNull();
});

it('only warns about back-channel logout the IdP does not fully support', function (array $discoveryOverrides, string $detail): void {
    FakeIdentityProvider::fake()->withDiscovery($discoveryOverrides);

    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe(0)
        ->and(collect($report['checks'])->firstWhere('check', 'back-channel logout'))
        ->toBe(['check' => 'back-channel logout', 'status' => 'warning', 'detail' => $detail]);
})->with([
    'not advertised' => [
        ['backchannel_logout_supported' => null, 'backchannel_logout_session_supported' => null],
        'The IdP does not advertise backchannel_logout_supported: a logout at the IdP may not end local sessions.',
    ],
    'without sid' => [
        ['backchannel_logout_session_supported' => false],
        'The IdP does not advertise backchannel_logout_session_supported: its logout tokens carry no sid, so each logout ends every session of the user.',
    ],
]);

it('checks front-channel support only when front-channel logout is on', function (array $discoveryOverrides, string $status, string $detail): void {
    FakeIdentityProvider::fake(configOverrides: ['frontchannel_logout.enabled' => true])->withDiscovery($discoveryOverrides);

    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe(0)
        ->and(collect($report['checks'])->firstWhere('check', 'front-channel support'))
        ->toBe(['check' => 'front-channel support', 'status' => $status, 'detail' => $detail]);
})->with([
    'with session' => [
        ['frontchannel_logout_supported' => true, 'frontchannel_logout_session_supported' => true],
        'ok',
        'The IdP supports front-channel logout with iss and sid.',
    ],
    'without session' => [
        ['frontchannel_logout_supported' => true],
        'warning',
        'oidc.frontchannel_logout.enabled is on but the IdP does not advertise frontchannel_logout_supported and frontchannel_logout_session_supported.',
    ],
    'session only' => [
        ['frontchannel_logout_session_supported' => true],
        'warning',
        'oidc.frontchannel_logout.enabled is on but the IdP does not advertise frontchannel_logout_supported and frontchannel_logout_session_supported.',
    ],
]);

it('compares the requested acr values with the advertised ones', function (?string $requestedAcrValues, mixed $acrValuesSupported, ?array $expectedCheck): void {
    FakeIdentityProvider::fake(configOverrides: ['mfa.request_acr_values' => $requestedAcrValues])
        ->withDiscovery(['acr_values_supported' => $acrValuesSupported]);

    [$exitCode, $report] = configureOidc();

    expect($exitCode)->toBe(0)
        ->and(collect($report['checks'])->firstWhere('check', 'acr values'))->toBe($expectedCheck);
})->with([
    'all advertised' => ['gold silver', ['bronze', 'silver', 'gold'], ['check' => 'acr values', 'status' => 'ok', 'detail' => 'The IdP advertises every requested acr value.']],
    'some missing' => ['gold platinum silver', ['silver'], ['check' => 'acr values', 'status' => 'warning', 'detail' => 'oidc.mfa.request_acr_values asks for gold, platinum, which the IdP does not list in acr_values_supported.']],
    'not advertised' => ['gold', null, null],
    'nothing requested' => [null, ['silver'], null],
    'empty request' => ['', ['silver'], null],
]);
