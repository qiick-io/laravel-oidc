<?php

declare(strict_types=1);

/*
 * Links the conformance suite's test user to a local user for every RP alias.
 *
 * The suite's user has `email_verified: false`, which the package refuses for JIT
 * provisioning and auto-linking by design; an existing (issuer, sub) link is step 1
 * of the linking rules and signs in regardless of the email.
 *
 * Run from the harness app root: php seed.php
 */

use App\Models\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Str;
use Qiick\Oidc\Models\UserIdentity;

require __DIR__.'/vendor/autoload.php';

$application = require __DIR__.'/bootstrap/app.php';
$application->make(Kernel::class)->bootstrap();

$suiteBaseUrl = rtrim(getenv('CONFORMANCE_SUITE_PUBLIC_URL') ?: 'https://nginx:8443', '/');
$suiteSubject = 'user-subject-1234531';

$user = User::query()->firstOrCreate(
    ['email' => 'user@example.com'],
    ['name' => 'Conformance Suite User', 'password' => Str::password(32)],
);

foreach (['rp-basic', 'rp-config', 'rp-logout', 'rp-backchannel', 'rp-frontchannel'] as $alias) {
    UserIdentity::query()->firstOrCreate(
        ['issuer' => "{$suiteBaseUrl}/test/a/{$alias}/", 'subject' => $suiteSubject],
        ['user_id' => $user->getKey(), 'public_id' => (string) Str::uuid(), 'link_method' => 'conformance-harness'],
    );
}

fwrite(STDOUT, "Linked {$suiteSubject} to {$user->email} for five RP aliases.\n");
