<?php

declare(strict_types=1);

namespace Qiick\Oidc\Tests\Support;

use Closure;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use RuntimeException;
use Throwable;

/**
 * Runs two pieces of work as two real processes with their own database
 * connections, interleaved at a chosen query: the parent runs its work, and
 * right after the query that `$shouldPauseAfter` picks, it forks a child that
 * runs the other work, pauses long enough for the child to reach its first
 * lock, then carries on and waits for the child.
 *
 * Only PostgreSQL and MySQL / MariaDB can race this way: SQLite has a single
 * writer. The pattern follows signaculum-core's tests/Concurrency.
 */
final class ProcessRace
{
    /**
     * Seconds the parent waits after forking, so the child is blocked on the
     * parent's uncommitted row (or past it) before the parent commits.
     */
    private const float CHILD_HEAD_START_SECONDS = 1.5;

    public static function isSupported(): bool
    {
        return in_array(DB::getDriverName(), ['pgsql', 'mysql', 'mariadb'], true) && function_exists('pcntl_fork');
    }

    /**
     * @param  Closure(QueryExecuted): bool  $shouldPauseAfter
     * @return array{parent: mixed, child: mixed} what each side returned, or
     *                                            ['exception' => class, 'message' => text] for what it threw
     */
    public static function run(Closure $shouldPauseAfter, Closure $parentWork, Closure $childWork): array
    {
        $resultFile = tempnam(sys_get_temp_dir(), 'oidc-race-') ?: throw new RuntimeException('No temporary file for the race result.');
        $childProcessId = null;

        DB::listen(function (QueryExecuted $query) use ($shouldPauseAfter, $childWork, $resultFile, &$childProcessId): void {
            if ($childProcessId !== null || ! $shouldPauseAfter($query)) {
                return;
            }

            $childProcessId = pcntl_fork();

            if ($childProcessId === -1) {
                throw new RuntimeException('pcntl_fork() failed.');
            }

            if ($childProcessId === 0) {
                self::runChild($childWork, $resultFile);
            }

            usleep((int) (self::CHILD_HEAD_START_SECONDS * 1_000_000));
        });

        $parentResult = self::outcome($parentWork);

        if ($childProcessId === null) {
            throw new RuntimeException('The parent work never ran the query to pause after.');
        }

        pcntl_waitpid($childProcessId, $childStatus);
        $childResult = unserialize((string) file_get_contents($resultFile));
        unlink($resultFile);

        return ['parent' => $parentResult, 'child' => $childResult];
    }

    /**
     * The child keeps the parent's connection object alive (closing it would
     * end the parent's database session, which shares the socket), opens its
     * own, runs the work, writes the outcome and ends without shutdown
     * handlers or destructors, which would touch the parent's socket.
     */
    private static function runChild(Closure $childWork, string $resultFile): never
    {
        $GLOBALS['inheritedDatabaseConnection'] = DB::connection()->getPdo();
        DB::connection()->setPdo(null)->setReadPdo(null);
        DB::reconnect();

        try {
            file_put_contents($resultFile, serialize(self::outcome($childWork)));
        } finally {
            posix_kill(posix_getpid(), SIGKILL);
        }

        exit(1);
    }

    private static function outcome(Closure $work): mixed
    {
        try {
            return $work();
        } catch (Throwable $exception) {
            return ['exception' => $exception::class, 'message' => $exception->getMessage()];
        }
    }
}
