<?php

declare(strict_types=1);

/**
 * Seeds a throwaway Zitadel instance for `pest --group=zitadel`.
 *
 * Uses the first-instance machine-user PAT written by `start-from-init` to
 * create the project, roles, OIDC app, human user and user grant via the
 * Management / User v2 APIs. Writes credentials JSON for the Pest suite.
 *
 * Env: ZITADEL_URL, ZITADEL_PAT (or ZITADEL_PAT_PATH), ZITADEL_CREDENTIALS.
 */
$zitadelUrl = rtrim((string) getenv('ZITADEL_URL'), '/');
$credentialsPath = getenv('ZITADEL_CREDENTIALS') ?: sys_get_temp_dir().'/laravel-oidc-zitadel-credentials.json';
$pat = getenv('ZITADEL_PAT') ?: '';

if ($pat === '') {
    $patPath = getenv('ZITADEL_PAT_PATH') ?: '';

    if (! is_string($patPath) || $patPath === '' || ! is_file($patPath)) {
        fwrite(STDERR, "Set ZITADEL_PAT or ZITADEL_PAT_PATH to the first-instance PAT.\n");
        exit(1);
    }

    $pat = trim((string) file_get_contents($patPath));
}

if ($zitadelUrl === '' || $pat === '') {
    fwrite(STDERR, "ZITADEL_URL and a non-empty PAT are required.\n");
    exit(1);
}

/**
 * @param  array<string, mixed>|null  $body
 * @return array<string, mixed>
 */
function zitadelRequest(string $method, string $url, string $pat, ?array $body = null): array
{
    $headers = [
        'Authorization: Bearer '.$pat,
        'Accept: application/json',
    ];
    $curlHandle = curl_init($url);

    if ($curlHandle === false) {
        throw new RuntimeException('curl_init failed.');
    }

    $options = [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_TIMEOUT => 30,
    ];

    if ($body !== null) {
        $headers[] = 'Content-Type: application/json';
        $options[CURLOPT_HTTPHEADER] = $headers;
        $options[CURLOPT_POSTFIELDS] = json_encode($body, JSON_THROW_ON_ERROR);
    }

    curl_setopt_array($curlHandle, $options);
    $responseBody = curl_exec($curlHandle);
    $statusCode = (int) curl_getinfo($curlHandle, CURLINFO_RESPONSE_CODE);
    $curlError = curl_error($curlHandle);
    curl_close($curlHandle);

    if (! is_string($responseBody) || $responseBody === '' || $statusCode < 200 || $statusCode >= 300) {
        throw new RuntimeException("Zitadel {$method} {$url} failed ({$statusCode}): {$curlError} {$responseBody}");
    }

    /** @var array<string, mixed> */
    return json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);
}

$password = 'Ci-only-Password1!';

$project = zitadelRequest('POST', $zitadelUrl.'/management/v1/projects', $pat, [
    'name' => 'laravel-oidc',
    'projectRoleAssertion' => true,
    'projectRoleCheck' => false,
    'hasProjectCheck' => false,
]);
$projectId = (string) $project['id'];

foreach (['admin', 'member'] as $roleKey) {
    zitadelRequest('POST', $zitadelUrl.'/management/v1/projects/'.$projectId.'/roles', $pat, [
        'roleKey' => $roleKey,
        'displayName' => $roleKey,
    ]);
}

$application = zitadelRequest('POST', $zitadelUrl.'/management/v1/projects/'.$projectId.'/apps/oidc', $pat, [
    'name' => 'laravel-app',
    'redirectUris' => ['http://localhost/auth/oidc/callback'],
    // Exact match with Testbench's UrlGenerator::to('/') → http://localhost
    'postLogoutRedirectUris' => ['http://localhost'],
    'responseTypes' => ['OIDC_RESPONSE_TYPE_CODE'],
    'grantTypes' => ['OIDC_GRANT_TYPE_AUTHORIZATION_CODE'],
    'appType' => 'OIDC_APP_TYPE_WEB',
    'authMethodType' => 'OIDC_AUTH_METHOD_TYPE_BASIC',
    'version' => 'OIDC_VERSION_1_0',
    'devMode' => true,
    'accessTokenType' => 'OIDC_TOKEN_TYPE_BEARER',
    'accessTokenRoleAssertion' => true,
    'idTokenRoleAssertion' => true,
    'idTokenUserinfoAssertion' => true,
]);

$user = zitadelRequest('POST', $zitadelUrl.'/v2/users/human', $pat, [
    'username' => 'ada',
    'profile' => [
        'givenName' => 'Ada',
        'familyName' => 'Lovelace',
        'displayName' => 'Ada Lovelace',
    ],
    'email' => [
        'email' => 'ada@example.com',
        'isVerified' => true,
    ],
    'password' => [
        'password' => $password,
        'changeRequired' => false,
    ],
]);
$userId = (string) $user['userId'];

zitadelRequest('POST', $zitadelUrl.'/management/v1/users/'.$userId.'/grants', $pat, [
    'projectId' => $projectId,
    'roleKeys' => ['member'],
]);

// Org login policy without MFA setup prompts so Guzzle can finish the code flow.
zitadelRequest('POST', $zitadelUrl.'/management/v1/policies/login', $pat, [
    'allowUsernamePassword' => true,
    'allowRegister' => false,
    'allowExternalIdp' => false,
    'forceMfa' => false,
    'forceMfaLocalOnly' => false,
    'passwordlessType' => 'PASSWORDLESS_TYPE_NOT_ALLOWED',
    'hidePasswordReset' => true,
    'ignoreUnknownUsernames' => false,
    'defaultRedirectUri' => '',
    'passwordCheckLifetime' => '864000s',
    'externalLoginCheckLifetime' => '864000s',
    'mfaInitSkipLifetime' => '0s',
    'secondFactorCheckLifetime' => '64800s',
    'multiFactorCheckLifetime' => '43200s',
    'secondFactors' => [],
    'multiFactors' => [],
    'allowDomainDiscovery' => true,
    'disableLoginWithEmail' => false,
    'disableLoginWithPhone' => true,
]);

$credentials = [
    'issuer' => $zitadelUrl,
    'client_id' => (string) $application['clientId'],
    'client_secret' => (string) $application['clientSecret'],
    'project_id' => $projectId,
    'role_claim' => 'urn:zitadel:iam:org:project:roles',
    'users' => [
        'ada' => [
            'login_name' => 'ada',
            'email' => 'ada@example.com',
            'password' => $password,
            'user_id' => $userId,
        ],
    ],
];

file_put_contents(
    $credentialsPath,
    json_encode($credentials, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES).PHP_EOL,
);

echo "Wrote {$credentialsPath}\n";
