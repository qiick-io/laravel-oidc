<?php

declare(strict_types=1);

use Illuminate\Http\Client\Factory as HttpFactory;
use Qiick\Oidc\Exceptions\IdentityProviderRequestException;
use Qiick\Oidc\Services\IdentityProviderHttpService;
use Qiick\Outbound\Http\HttpRequestOptions;
use Qiick\Outbound\Http\OutboundHttpLimits;
use Qiick\Outbound\Http\OutboundRequest;
use Qiick\Outbound\Http\PinnedHttpClient;
use Qiick\Outbound\Ssrf\RemoteUrlGuard;
use Qiick\Outbound\Ssrf\UrlGuardOptions;
use Qiick\Outbound\Testing\FakeHostResolver;

/**
 * Real Guzzle+curl transport against php -S for the OIDC IdP HTTP path.
 *
 * @group real-transport
 */
final class OidcRealTransportServer
{
    public string $captureDir;

    public string $pinAddress = '127.0.0.1';

    public int $port;

    /** @var resource */
    public $process;

    public PinnedHttpClient $client;

    public IdentityProviderHttpService $identityProviderHttp;

    public function __construct(?int $maxResponseBytes = 1_048_576)
    {
        $this->captureDir = sys_get_temp_dir().'/oidc-rt-'.bin2hex(random_bytes(8));
        mkdir($this->captureDir, 0700, true);

        $router = dirname(__DIR__, 2).'/Support/real-transport-server.php';
        $this->process = $this->startPhpServer($router);
        $this->waitUntilAcceptingConnections();

        $resolver = (new FakeHostResolver)
            ->with('app.test', [$this->pinAddress])
            ->with('evil.test', [$this->pinAddress]);

        $guard = new RemoteUrlGuard($resolver, allowPrivateHosts: true, httpsOnly: false);
        $this->client = new PinnedHttpClient(
            new HttpFactory,
            $guard,
            new OutboundHttpLimits,
        );
        $this->identityProviderHttp = new IdentityProviderHttpService(
            $this->client,
            new UrlGuardOptions(httpsOnly: false, allowPrivateHosts: true),
            timeoutSeconds: 5,
            connectTimeoutSeconds: 2,
            maxResponseBytes: $maxResponseBytes ?? 1_048_576,
        );
    }

    /**
     * @return resource
     */
    private function startPhpServer(string $router)
    {
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['file', $this->captureDir.'/server.out', 'w'],
            2 => ['file', $this->captureDir.'/server.err', 'w'],
        ];

        for ($attempt = 0; $attempt < 20; $attempt++) {
            $port = $this->allocateFreePort();
            $cmd = sprintf(
                'REAL_TRANSPORT_CAPTURE_DIR=%s %s -S %s:%d %s',
                escapeshellarg($this->captureDir),
                escapeshellarg(PHP_BINARY),
                $this->pinAddress,
                $port,
                escapeshellarg($router),
            );

            $pipes = [];
            $process = proc_open($cmd, $descriptors, $pipes);

            if (! is_resource($process)) {
                throw new RuntimeException('Failed to start php -S for real-transport tests.');
            }

            usleep(30_000);
            $status = proc_get_status($process);
            $err = @file_get_contents($this->captureDir.'/server.err') ?: '';

            if (($status['running'] ?? false) === true && ! str_contains($err, 'Address already in use')) {
                $this->port = $port;

                return $process;
            }

            proc_terminate($process);
            proc_close($process);
            @unlink($this->captureDir.'/server.err');
            @unlink($this->captureDir.'/server.out');
        }

        throw new RuntimeException('Failed to bind php -S to a free loopback port.');
    }

    private function allocateFreePort(): int
    {
        $socket = @stream_socket_server('tcp://'.$this->pinAddress.':0', $errno, $errstr);

        if ($socket === false) {
            throw new RuntimeException('Failed to allocate a free port: '.$errstr);
        }

        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        if (! is_string($name) || ! str_contains($name, ':')) {
            throw new RuntimeException('Failed to read allocated port name.');
        }

        return (int) substr($name, strrpos($name, ':') + 1);
    }

    private function waitUntilAcceptingConnections(): void
    {
        $deadline = microtime(true) + 10;
        $lastError = 'timeout';

        while (microtime(true) < $deadline) {
            $status = proc_get_status($this->process);

            if (is_array($status) && ($status['running'] ?? false) !== true) {
                $err = @file_get_contents($this->captureDir.'/server.err') ?: '';

                throw new RuntimeException('php -S exited before accepting connections: '.$err);
            }

            $errno = 0;
            $errstr = '';
            $fp = @fsockopen($this->pinAddress, $this->port, $errno, $errstr, 0.25);

            if (is_resource($fp)) {
                fclose($fp);

                $probe = @file_get_contents(
                    'http://'.$this->pinAddress.':'.$this->port.'/ok',
                    false,
                    stream_context_create([
                        'http' => [
                            'method' => 'GET',
                            'timeout' => 0.5,
                            'header' => "Host: app.test\r\n",
                            'ignore_errors' => true,
                        ],
                    ]),
                );

                if (is_string($probe) && str_contains($probe, '"ok":true')) {
                    return;
                }

                $lastError = 'port open but /ok not ready';
            } else {
                $lastError = $errstr !== '' ? $errstr : 'errno '.$errno;
            }

            usleep(50_000);
        }

        throw new RuntimeException('php -S did not accept connections on '.$this->pinAddress.':'.$this->port.' ('.$lastError.')');
    }

    public function stop(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }

        foreach (glob($this->captureDir.'/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->captureDir);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function capture(string $name, float $timeoutSeconds = 2.0): ?array
    {
        $path = $this->captureDir.'/'.$name.'.json';
        $deadline = microtime(true) + max(0.0, $timeoutSeconds);

        do {
            if (is_file($path)) {
                $raw = @file_get_contents($path);

                if (is_string($raw) && $raw !== '') {
                    return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
                }
            }

            if ($timeoutSeconds <= 0.0 || microtime(true) >= $deadline) {
                break;
            }

            usleep(20_000);
        } while (microtime(true) < $deadline);

        return null;
    }

    public function url(string $host, string $path): string
    {
        return 'http://'.$host.':'.$this->port.$path;
    }
}

it('pins IdentityProviderHttpService through real curl CONNECT_TO', function (): void {
    $server = new OidcRealTransportServer;

    putenv('http_proxy=http://127.0.0.1:9');
    putenv('HTTP_PROXY=http://127.0.0.1:9');
    putenv('https_proxy=http://127.0.0.1:9');
    putenv('HTTPS_PROXY=http://127.0.0.1:9');
    putenv('ALL_PROXY=http://127.0.0.1:9');

    try {
        $payload = $server->identityProviderHttp->getJson($server->url('app.test', '/token'));

        expect($payload)->toBe(['ok' => true, 'host' => 'app.test:'.$server->port]);

        $capture = $server->capture('token');
        expect($capture)->not->toBeNull()
            ->and($capture['host'])->toBe('app.test:'.$server->port)
            ->and($capture['path'])->toBe('/token');
    } finally {
        putenv('http_proxy');
        putenv('HTTP_PROXY');
        putenv('https_proxy');
        putenv('HTTPS_PROXY');
        putenv('ALL_PROXY');
        $server->stop();
    }
})->group('real-transport');

it('enforces max response bytes on the real wire', function (): void {
    $server = new OidcRealTransportServer(maxResponseBytes: 64);

    try {
        expect(fn () => $server->identityProviderHttp->getJson($server->url('app.test', '/big?n=128')))
            ->toThrow(IdentityProviderRequestException::class, 'connection error');
    } finally {
        $server->stop();
    }
})->group('real-transport');

it('strips Authorization on an opted-in cross-origin 302 on the real wire', function (): void {
    $server = new OidcRealTransportServer;

    try {
        $server->client->send(
            'POST',
            $server->url('app.test', '/redirect-cross-302'),
            function (OutboundRequest $request): void {
                $request->withBody('super-secret-body', 'text/plain')
                    ->withHeader('Authorization', 'Bearer real-leak');
            },
            new HttpRequestOptions(
                timeoutSeconds: 3,
                connectTimeoutSeconds: 2,
                followRedirects: true,
                maxRedirects: 2,
                allowCrossOriginRedirects: true,
                urlOptions: new UrlGuardOptions(httpsOnly: false, allowPrivateHosts: true),
            ),
        );

        $first = $server->capture('redirect-cross-302');
        $second = $server->capture('steal');

        expect($first)->not->toBeNull()
            ->and($first['authorization'])->toContain('Bearer real-leak')
            ->and($first['body'])->toBe('super-secret-body')
            ->and($second)->not->toBeNull()
            ->and($second['authorization'])->toBe('')
            ->and($second['body'])->toBe('')
            ->and($second['method'])->toBe('GET');
    } finally {
        $server->stop();
    }
})->group('real-transport');
