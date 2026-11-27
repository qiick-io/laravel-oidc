<?php

declare(strict_types=1);

namespace Qiick\Oidc\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Config;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;

/**
 * Checks the deployed OIDC setup without accepting overrides or writing .env.
 */
final class CheckOidcCommand extends Command
{
    protected $signature = 'oidc:check';

    protected $description = 'Validate the active OpenID Connect setup for deployment';

    public function handle(ProviderConfigurationRepositoryContract $configurationRepository): int
    {
        if (! Config::boolean('oidc.enabled') && ! $configurationRepository->isEnabled()) {
            $this->info('OIDC is disabled.');

            return self::SUCCESS;
        }

        return $this->call('oidc:configure');
    }
}
