<?php

declare(strict_types=1);

/**
 * Router script for real-transport Pest tests (php -S).
 * Writes hop captures under the directory in REAL_TRANSPORT_CAPTURE_DIR.
 */
$captureDir = getenv('REAL_TRANSPORT_CAPTURE_DIR') ?: sys_get_temp_dir();
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$body = file_get_contents('php://input') ?: '';
$host = $_SERVER['HTTP_HOST'] ?? '';

$query = $_SERVER['QUERY_STRING'] ?? '';
$record = static function (string $name) use ($captureDir, $method, $path, $body, $host, $query): void {
    $payload = json_encode([
        'method' => $method,
        'path' => $path,
        'query' => $query,
        'host' => $host,
        'server_addr' => $_SERVER['SERVER_ADDR'] ?? '',
        'server_port' => (string) ($_SERVER['SERVER_PORT'] ?? ''),
        'authorization' => $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? ''),
        'cookie' => $_SERVER['HTTP_COOKIE'] ?? '',
        'proxy_authorization' => $_SERVER['HTTP_PROXY_AUTHORIZATION'] ?? '',
        'x_api_key' => $_SERVER['HTTP_X_API_KEY'] ?? '',
        'accept' => $_SERVER['HTTP_ACCEPT'] ?? '',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'body' => $body,
        'content_length' => $_SERVER['CONTENT_LENGTH'] ?? '',
    ], JSON_THROW_ON_ERROR);

    $target = $captureDir.'/'.$name.'.json';
    $tmp = $captureDir.'/'.$name.'.'.bin2hex(random_bytes(4)).'.tmp';

    if (file_put_contents($tmp, $payload) === false) {
        throw new RuntimeException('Failed to write real-transport capture temp file.');
    }

    if (! rename($tmp, $target)) {
        @unlink($tmp);

        throw new RuntimeException('Failed to publish real-transport capture file.');
    }
};

if ($path === '/ok' || $path === '/token') {
    $record($path === '/token' ? 'token' : 'ok');
    header('Content-Type: application/json');
    echo json_encode(['ok' => true, 'host' => $host], JSON_THROW_ON_ERROR);

    return true;
}

if ($path === '/big') {
    $record('big');
    $size = (int) ($_GET['n'] ?? 2_000_000);
    header('Content-Type: application/octet-stream');
    header('Content-Length: '.$size);
    echo str_repeat('x', $size);

    return true;
}

if ($path === '/redirect-cross-302') {
    $record('redirect-cross-302');
    $port = $_SERVER['SERVER_PORT'] ?? '80';
    header('Location: http://evil.test:'.$port.'/steal', true, 302);

    return true;
}

if ($path === '/steal') {
    $record('steal');
    header('Content-Type: application/json');
    echo '{"stolen":true}';

    return true;
}

http_response_code(404);
header('Content-Type: application/json');
echo '{"error":"not_found"}';

return true;
