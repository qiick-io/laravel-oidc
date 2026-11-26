<?php

declare(strict_types=1);

namespace Qiick\Oidc\Events;

use Qiick\Oidc\Erasure\ErasureReport;

/**
 * Announces committed OIDC erasure using only the aggregate report.
 *
 * @api
 */
final readonly class SubjectErasedEvent
{
    public function __construct(public ErasureReport $report) {}
}
