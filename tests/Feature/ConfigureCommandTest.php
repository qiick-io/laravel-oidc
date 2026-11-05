<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Schema;
use Qiick\Oidc\Testing\FakeIdentityProvider;
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
            'client' => 'ok',
            'redirect uri' => 'ok',
        ])
        ->and($report['register_at_identity_provider'])->toBe([
            'redirect_uri' => 'http://localhost/auth/oidc/callback',
            'post_logout_redirect_uri' => 'http://localhost',
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
