<?php

declare(strict_types=1);

/**
 * Seeds a throwaway Signaculum instance for the Pest group `signaculum`.
 *
 * Run from the Signaculum tree after migrate + Passport keys + a signing key:
 *
 *   SIGNACULUM_URL=http://127.0.0.1:8090 \
 *   SIGNACULUM_BACKCHANNEL_URI=http://127.0.0.1:8091/backchannel-logout \
 *   php /path/to/laravel-oidc/tests/Fixtures/signaculum/seed-idp.php
 *
 * Writes credentials.json next to this script (gitignored via the directory
 * convention: only committed fixtures live beside it; credentials are runtime).
 */

use App\Enums\OrganizationRoleEnum;
use App\Models\Client;
use App\Models\Organization;
use App\Models\OrganizationMembership;
use App\Models\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\ClientRepository;
use PragmaRX\Google2FA\Google2FA;

$signaculumRoot = getenv('SIGNACULUM_DIR');

if (! is_string($signaculumRoot) || $signaculumRoot === '' || ! is_file($signaculumRoot.'/bootstrap/app.php')) {
    fwrite(STDERR, "SIGNACULUM_DIR must point at a Signaculum checkout with vendor installed.\n");
    exit(1);
}

$issuer = rtrim((string) (getenv('SIGNACULUM_URL') ?: 'http://127.0.0.1:8090'), '/');
$backchannelUri = (string) (getenv('SIGNACULUM_BACKCHANNEL_URI') ?: 'http://127.0.0.1:8091/backchannel-logout');
$redirectUri = (string) (getenv('SIGNACULUM_REDIRECT_URI') ?: 'http://localhost/auth/oidc/callback');
$postLogoutRedirectUri = (string) (getenv('SIGNACULUM_POST_LOGOUT_REDIRECT_URI') ?: 'http://localhost/');
$credentialsPath = getenv('SIGNACULUM_CREDENTIALS') ?: (__DIR__.'/credentials.json');

require $signaculumRoot.'/vendor/autoload.php';

/** @var Application $app */
$app = require $signaculumRoot.'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$config = $app->make('config');
$config->set('app.url', $issuer);
$config->set('oidc.issuer', $issuer);

$google2fa = new Google2FA;
$totpSecret = $google2fa->generateSecretKey();

$ada = User::query()->firstOrNew(['email' => 'ada@example.com']);
$ada->fill([
    'first_name' => 'Ada',
    'last_name' => 'Lovelace',
    'password' => Hash::make('password'),
]);
$ada->forceFill([
    'email_verified_at' => now(),
    'is_active' => true,
    // Signaculum dropped users.is_instance_admin for Spatie roles (#206).
    'two_factor_secret' => null,
    'two_factor_recovery_codes' => null,
    'two_factor_confirmed_at' => null,
])->save();

$mfaUser = User::query()->firstOrNew(['email' => 'mfa@example.com']);
$mfaUser->fill([
    'first_name' => 'Grace',
    'last_name' => 'Hopper',
    'password' => Hash::make('password'),
]);
$mfaUser->forceFill([
    'email_verified_at' => now(),
    'is_active' => true,
    'two_factor_secret' => encrypt($totpSecret),
    'two_factor_recovery_codes' => encrypt(json_encode(['recovery-code-ci-only'])),
    'two_factor_confirmed_at' => now(),
])->save();

$organization = Organization::query()->updateOrCreate(
    ['slug' => 'acme'],
    ['name' => 'Acme'],
);

foreach ([$ada, $mfaUser] as $member) {
    OrganizationMembership::query()->updateOrCreate(
        [
            'organization_id' => $organization->getKey(),
            'user_id' => $member->getKey(),
        ],
        [
            'roles' => [
                OrganizationRoleEnum::Member->value,
                OrganizationRoleEnum::Admin->value,
            ],
        ],
    );
}

/** @var ClientRepository $clientRepository */
$clientRepository = $app->make(ClientRepository::class);

$existingClient = Client::query()->where('name', 'laravel-oidc-e2e')->first();

if ($existingClient instanceof Client) {
    $existingClient->tokens()->delete();
    $existingClient->delete();
}

/** @var Client $client */
$client = $clientRepository->createAuthorizationCodeGrantClient(
    'laravel-oidc-e2e',
    [$redirectUri],
    true,
);

$plainSecret = $client->plainSecret;

$client->forceFill([
    'is_first_party' => true,
    'grant_types' => ['authorization_code', 'refresh_token'],
    'post_logout_redirect_uris' => [$postLogoutRedirectUri],
    'backchannel_logout_uri' => $backchannelUri,
    'is_backchannel_logout_session_required' => true,
])->save();

$client->plainSecret = $plainSecret;

$credentials = [
    'issuer' => $issuer,
    'client_id' => (string) $client->getKey(),
    'client_secret' => (string) $plainSecret,
    'organization_id' => (string) $organization->getKey(),
    'organization_slug' => 'acme',
    'redirect_uri' => $redirectUri,
    'post_logout_redirect_uri' => $postLogoutRedirectUri,
    'backchannel_logout_uri' => $backchannelUri,
    'users' => [
        'ada' => [
            'email' => 'ada@example.com',
            'password' => 'password',
        ],
        'mfa' => [
            'email' => 'mfa@example.com',
            'password' => 'password',
            'totp_secret' => $totpSecret,
        ],
    ],
];

file_put_contents(
    $credentialsPath,
    json_encode($credentials, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES).PHP_EOL,
);

fwrite(STDOUT, json_encode([
    'credentials_path' => $credentialsPath,
    'client_id' => $credentials['client_id'],
    'organization_slug' => $credentials['organization_slug'],
], JSON_UNESCAPED_SLASHES).PHP_EOL);
