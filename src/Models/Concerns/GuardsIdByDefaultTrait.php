<?php

declare(strict_types=1);

namespace Qiick\Oidc\Models\Concerns;

/**
 * Guards only the `id` column of a package model, unless an app subclass
 * declares its own `$guarded` or `$fillable`: the app's choice always wins.
 *
 * Eloquent calls initialize<Trait>() from the model constructor, so this
 * replaces a `protected $guarded = ['id']` declaration that a subclass would
 * otherwise have to repeat to change.
 */
trait GuardsIdByDefaultTrait
{
    protected function initializeGuardsIdByDefaultTrait(): void
    {
        $isGuardingLeftAtEloquentDefault = $this->guarded === ['*'] && $this->fillable === [];

        if ($isGuardingLeftAtEloquentDefault) {
            $this->guarded = ['id'];
        }
    }
}
