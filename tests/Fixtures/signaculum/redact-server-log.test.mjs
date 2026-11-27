import assert from 'node:assert/strict';
import { test } from 'node:test';
import { redactServerLog } from './redact-server-log.mjs';

test('keeps server events and masks request targets and exception details', () => {
    const log = [
        '  \x1b[44m INFO \x1b[0m Server running on [http://127.0.0.1:8090].',
        '[Fri Nov 27 12:00:00 2026] PHP 8.4.0 Development Server (http://127.0.0.1:8091) started',
        '[Fri Nov 27 12:00:01 2026] 127.0.0.1:50200 Accepted',
        '[Fri Nov 27 12:00:01 2026] 127.0.0.1:50200 [500]: POST /private?code=fake-code',
        '[Fri Nov 27 12:00:01 2026] 127.0.0.1:50200 Closing',
        '  2026-11-27 12:00:02 /oauth/authorize?state=fake-state ........ ~ 12.5ms',
        '  PHP Fatal error:  Uncaught exception in /private/app/Server.php:23',
        'Failed to listen on 127.0.0.1:8090 (reason: Address already in use)',
        '',
    ].join('\n');

    assert.equal(redactServerLog(log), [
        'Loopback server started.',
        'Loopback server started.',
        'Loopback connection accepted.',
        'HTTP POST 500.',
        'Loopback connection closed.',
        'Laravel server handled a request.',
        'PHP server error [redacted].',
        'Loopback server failed to bind.',
        '',
    ].join('\n'));
});

test('masks unstructured output even when it contains no known secret format', () => {
    const log = [
        'Authorization: Bearer fake-jwt',
        'Cookie: session=fake-cookie',
        'APP_KEY=base64:fake-app-key',
        'private source: return "arbitrary fixture credential";',
        '::warning::unexpected runner command',
        '',
    ].join('\n');

    assert.equal(redactServerLog(log), '[redacted]\n'.repeat(5));
});
