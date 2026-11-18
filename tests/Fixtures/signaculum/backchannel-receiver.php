<?php

declare(strict_types=1);

/**
 * Tiny HTTP receiver for Signaculum back-channel logout during e2e.
 *
 *   SIGNACULUM_BACKCHANNEL_CAPTURE=/tmp/logout-token.txt \
 *   php -S 127.0.0.1:8091 tests/Fixtures/signaculum/backchannel-receiver.php
 *
 * Persists the raw `logout_token` form field so Pest can POST it into the
 * package's `/auth/oidc/backchannel-logout` route (Testbench is not a real
 * HTTP listener Signaculum can reach).
 */
$capturePath = getenv('SIGNACULUM_BACKCHANNEL_CAPTURE') ?: sys_get_temp_dir().'/laravel-oidc-signaculum-logout-token.txt';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if ($method === 'POST' && $path === '/backchannel-logout') {
    $logoutToken = $_POST['logout_token'] ?? null;

    if (! is_string($logoutToken) || $logoutToken === '') {
        http_response_code(400);
        header('Content-Type: text/plain; charset=UTF-8');
        echo "missing logout_token\n";

        return;
    }

    file_put_contents($capturePath, $logoutToken);
    http_response_code(200);
    header('Content-Type: text/plain; charset=UTF-8');
    header('Cache-Control: no-store');
    echo "ok\n";

    return;
}

http_response_code(404);
header('Content-Type: text/plain; charset=UTF-8');
echo "not found\n";
