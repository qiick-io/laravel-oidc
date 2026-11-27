import { readFileSync } from 'node:fs';

// Artifacts on a public repository are readable by signed-in users. Emit only
// known server events, since arbitrary paths and error text can contain secrets.
function describeServerEvent(line) {
    if (/^(?:INFO +)?Server running on \[http:\/\/127\.0\.0\.1:\d+\]\.$/.test(line)
        || /^\[[^\]]+\] PHP [\d.]+ Development Server \(http:\/\/127\.0\.0\.1:\d+\) started$/.test(line)) {
        return 'Loopback server started.';
    }

    if (/^(?:\[[^\]]+\] )?Failed to listen on 127\.0\.0\.1:\d+ /.test(line)) {
        return 'Loopback server failed to bind.';
    }

    if (/^(?:\[[^\]]+\] )?PHP (?:Fatal|Parse) error:/.test(line)) {
        return 'PHP server error [redacted].';
    }

    const httpResponse = /^\[[^\]]+\] 127\.0\.0\.1:\d+ \[([1-5]\d\d)\]: (GET|POST|HEAD|OPTIONS) /.exec(line);
    if (httpResponse) {
        return `HTTP ${httpResponse[2]} ${httpResponse[1]}.`;
    }

    if (/^\[[^\]]+\] 127\.0\.0\.1:\d+ Accepted$/.test(line)) {
        return 'Loopback connection accepted.';
    }

    if (/^\[[^\]]+\] 127\.0\.0\.1:\d+ Closing$/.test(line)) {
        return 'Loopback connection closed.';
    }

    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} .*~ \d+(?:\.\d+)?m?s$/.test(line)) {
        return 'Laravel server handled a request.';
    }

    return '[redacted]';
}

export function redactServerLog(log) {
    return log.split('\n')
        .map((line) => line.replace(/\x1b\[[0-9;]*m/g, '').trim())
        .filter(Boolean)
        .map((line) => `${describeServerEvent(line)}\n`)
        .join('');
}

if (import.meta.main) {
    process.stdout.write(redactServerLog(readFileSync(0, 'utf8')));
}
