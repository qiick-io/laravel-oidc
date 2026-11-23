<?php

declare(strict_types=1);

namespace Qiick\Oidc\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Qiick\Oidc\Contracts\BreakGlassPolicyContract;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Data\DiscoveryDocumentData;
use Qiick\Oidc\Data\ProviderConfigurationData;
use Qiick\Oidc\Exceptions\OidcException;
use Qiick\Oidc\Models\UserIdentity;
use Qiick\Oidc\Services\DiscoveryService;
use Qiick\Oidc\Services\IdentityProviderHttpService;
use Qiick\Oidc\Services\JwtValidatorService;

/**
 * `php artisan oidc:configure`: checks an SSO setup end to end, so a human or
 * an agent can configure it without clicking through the login (design
 * section 4, "Agent-first").
 *
 * It reads the current settings, overridden by the options, then checks the
 * discovery document and the capabilities it advertises, the JWKS, the
 * signing algorithms, the redirect and logout URIs, that `app.timezone` is
 * UTC, the front-channel logout setup when it is on and, in SSO-only mode,
 * that a break-glass account exists. It
 * prints the URIs to register at the IdP. With `--write-env` it writes the
 * settings to `.env`, only when no check failed. `--json` prints a machine
 * readable report. The exit code is 0 without failures, 1 otherwise.
 *
 * It never prints the client secret.
 */
final class ConfigureOidcCommand extends Command
{
    protected $signature = 'oidc:configure
        {--issuer= : Issuer URL, exactly as the IdP publishes it}
        {--client-id= : Client id registered at the IdP}
        {--client-secret= : Client secret (omit for a public client)}
        {--write-env : Write OIDC_ENABLED, OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET to .env when every check passes}
        {--json : Print the report as JSON}';

    protected $description = 'Check the OpenID Connect setup against the IdP and print the URIs to register there';

    /**
     * @var list<array{check: string, status: 'ok'|'warning'|'failure', detail: string}>
     */
    private array $results = [];

    /**
     * The IdP's advertised capabilities (standards review S5), for the JSON
     * report; null until discovery succeeded.
     *
     * @var array<string, bool|list<string>|null>|null
     */
    private ?array $capabilities = null;

    public function handle(
        ProviderConfigurationRepositoryContract $configurationRepository,
        DiscoveryService $discovery,
        IdentityProviderHttpService $identityProviderHttp,
        BreakGlassPolicyContract $breakGlassPolicy,
    ): int {
        $this->applyOptions();
        $configuration = $this->resolveConfiguration($configurationRepository);

        if ($configuration !== null) {
            $discoveryDocument = $this->checkDiscovery($discovery, $configuration);

            if ($discoveryDocument !== null) {
                $this->checkSigningKeys($identityProviderHttp, $discoveryDocument);
                $this->checkCapabilities($discoveryDocument);
            }

            $this->checkClient($configuration);
            $this->checkRedirectUri($configuration->redirectUri);
            $this->checkTimezone();
            $this->checkFrontChannelLogout();
            $this->checkBreakGlass($breakGlassPolicy);
        }

        if (! $this->hasFailure() && $this->option('write-env')) {
            $this->writeEnvironment();
        }

        $hasFailure = $this->hasFailure();
        $urisToRegister = $configuration === null ? [] : $this->urisToRegister($configuration);

        $this->report($hasFailure, $urisToRegister);

        return $hasFailure ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Options override the current settings for this run only (and for
     * `--write-env`). SSO is treated as enabled while checking.
     */
    private function applyOptions(): void
    {
        foreach (['issuer' => 'oidc.issuer', 'client-id' => 'oidc.client_id', 'client-secret' => 'oidc.client_secret'] as $option => $configKey) {
            $value = $this->option($option);

            if (is_string($value) && $value !== '') {
                Config::set($configKey, $value);
            }
        }

        Config::set('oidc.enabled', true);
    }

    private function resolveConfiguration(ProviderConfigurationRepositoryContract $configurationRepository): ?ProviderConfigurationData
    {
        try {
            $configuration = $configurationRepository->configuration();
        } catch (OidcException) {
            $this->record('settings', 'failure', 'Issuer and client id are required (--issuer, --client-id or OIDC_ISSUER, OIDC_CLIENT_ID).');

            return null;
        }

        $this->record('settings', 'ok', "Issuer {$configuration->issuer}, client {$configuration->clientId}.");

        return $configuration;
    }

    private function checkDiscovery(DiscoveryService $discovery, ProviderConfigurationData $configuration): ?DiscoveryDocumentData
    {
        $discovery->forget($configuration);

        try {
            $discoveryDocument = $discovery->discover($configuration);
        } catch (OidcException $exception) {
            $this->record('discovery', 'failure', $exception->getMessage());

            return null;
        }

        $this->record('discovery', 'ok', 'Issuer matches; authorization code flow with PKCE S256 is available.');
        $this->record(
            'end session',
            $discoveryDocument->endSessionEndpoint === null ? 'warning' : 'ok',
            $discoveryDocument->endSessionEndpoint === null
                ? 'The IdP has no end_session_endpoint: logout ends the local session only.'
                : 'RP-initiated logout is available.',
        );

        return $discoveryDocument;
    }

    private function checkSigningKeys(IdentityProviderHttpService $identityProviderHttp, DiscoveryDocumentData $discoveryDocument): void
    {
        $allowedAlgorithms = array_intersect(JwtValidatorService::supportedAlgorithms(), $this->configuredStrings('oidc.id_token.algorithms'));
        $commonAlgorithms = array_intersect($allowedAlgorithms, $discoveryDocument->idTokenSigningAlgorithms);

        if ($commonAlgorithms === []) {
            $this->record('algorithms', 'failure', 'The IdP signs id_tokens with '.implode(', ', $discoveryDocument->idTokenSigningAlgorithms)
                .'; oidc.id_token.algorithms allows '.implode(', ', $allowedAlgorithms).'.');
        } else {
            $this->record('algorithms', 'ok', 'id_token signed with '.implode(', ', $commonAlgorithms).'.');
        }

        try {
            $publishedKeys = $identityProviderHttp->getJson($discoveryDocument->jwksUri)['keys'] ?? null;
        } catch (OidcException $exception) {
            $this->record('signing keys', 'failure', $exception->getMessage());

            return;
        }

        $signingKeys = array_filter(
            is_array($publishedKeys) ? $publishedKeys : [],
            fn (mixed $publishedKey): bool => is_array($publishedKey) && ($publishedKey['use'] ?? 'sig') === 'sig' && in_array($publishedKey['kty'] ?? null, ['RSA', 'EC'], true),
        );

        $this->record(
            'signing keys',
            $signingKeys === [] ? 'failure' : 'ok',
            $signingKeys === [] ? 'The JWKS has no RSA or EC signing key.' : count($signingKeys).' signing key(s) in the JWKS.',
        );
    }

    /**
     * Reports what the IdP advertises (DISC §3, BCL §2.1, FCL §3). Optional
     * metadata is never fatal: a missing capability is at most a warning.
     */
    private function checkCapabilities(DiscoveryDocumentData $discoveryDocument): void
    {
        $this->capabilities = [
            'frontchannel_logout_supported' => $discoveryDocument->isFrontChannelLogoutSupported,
            'frontchannel_logout_session_supported' => $discoveryDocument->isFrontChannelLogoutSessionSupported,
            'backchannel_logout_supported' => $discoveryDocument->isBackChannelLogoutSupported,
            'backchannel_logout_session_supported' => $discoveryDocument->isBackChannelLogoutSessionSupported,
            'acr_values_supported' => $discoveryDocument->acrValuesSupported,
            'claims_parameter_supported' => $discoveryDocument->isClaimsParameterSupported,
        ];

        if (! $discoveryDocument->isBackChannelLogoutSupported) {
            $this->record('back-channel logout', 'warning', 'The IdP does not advertise backchannel_logout_supported: a logout at the IdP may not end local sessions.');
        } elseif (! $discoveryDocument->isBackChannelLogoutSessionSupported) {
            $this->record('back-channel logout', 'warning', 'The IdP does not advertise backchannel_logout_session_supported: its logout tokens carry no sid, so each logout ends every session of the user.');
        } else {
            $this->record('back-channel logout', 'ok', 'The IdP sends back-channel logout tokens with sid.');
        }

        if (Config::boolean('oidc.frontchannel_logout.enabled')) {
            $isFrontChannelUsable = $discoveryDocument->isFrontChannelLogoutSupported && $discoveryDocument->isFrontChannelLogoutSessionSupported;

            $this->record(
                'front-channel support',
                $isFrontChannelUsable ? 'ok' : 'warning',
                $isFrontChannelUsable
                    ? 'The IdP supports front-channel logout with iss and sid.'
                    : 'oidc.frontchannel_logout.enabled is on but the IdP does not advertise frontchannel_logout_supported and frontchannel_logout_session_supported.',
            );
        }

        $requestedAcrValues = Config::get('oidc.mfa.request_acr_values');

        if (! is_string($requestedAcrValues) || $requestedAcrValues === '' || $discoveryDocument->acrValuesSupported === null) {
            return;
        }

        $unsupportedAcrValues = array_diff(explode(' ', $requestedAcrValues), $discoveryDocument->acrValuesSupported);

        $this->record(
            'acr values',
            $unsupportedAcrValues === [] ? 'ok' : 'warning',
            $unsupportedAcrValues === []
                ? 'The IdP advertises every requested acr value.'
                : 'oidc.mfa.request_acr_values asks for '.implode(', ', $unsupportedAcrValues).', which the IdP does not list in acr_values_supported.',
        );
    }

    private function checkClient(ProviderConfigurationData $configuration): void
    {
        $this->record(
            'client',
            $configuration->isPublicClient() ? 'warning' : 'ok',
            $configuration->isPublicClient()
                ? 'No client secret: the IdP client must be public (PKCE only).'
                : "Confidential client ({$configuration->tokenEndpointAuthMethod->value}).",
        );
    }

    private function checkRedirectUri(string $redirectUri): void
    {
        $scheme = parse_url($redirectUri, PHP_URL_SCHEME);
        $host = parse_url($redirectUri, PHP_URL_HOST);
        // parse_url() keeps the brackets around an IPv6 host.
        $isLocalHost = in_array($host, ['localhost', '127.0.0.1', '[::1]'], true) || (is_string($host) && str_ends_with($host, '.test'));

        if (! is_string($host) || ! in_array($scheme, ['http', 'https'], true)) {
            $this->record('redirect uri', 'failure', "[{$redirectUri}] is not an absolute URL. Set APP_URL or oidc.redirect_uri.");

            return;
        }

        if ($scheme === 'http' && ! $isLocalHost) {
            $this->record('redirect uri', 'warning', "[{$redirectUri}] uses plain http outside localhost; most IdPs refuse it.");

            return;
        }

        $this->record('redirect uri', 'ok', $redirectUri);
    }

    /**
     * The package stores `last_login_at`, `last_auth_time_at` and the logout
     * revocation times as plain `timestamp` columns, which carry no zone, and
     * reads them back in `app.timezone` (standards review M7 and R5). Only
     * UTC keeps them comparable across apps and with the IdP's epoch claims.
     */
    private function checkTimezone(): void
    {
        $timezone = Config::string('app.timezone');

        if ($timezone === 'UTC') {
            $this->record('timezone', 'ok', 'app.timezone is UTC.');

            return;
        }

        $this->record('timezone', 'warning', "app.timezone is {$timezone}; the package expects UTC in its timestamp columns, so set it to UTC.");
    }

    /**
     * In SSO-only mode at least one account must still be able to sign in
     * locally, or a broken IdP locks everyone out.
     */
    private function checkBreakGlass(BreakGlassPolicyContract $breakGlassPolicy): void
    {
        if (! Config::boolean('oidc.only')) {
            return;
        }

        foreach (UserIdentity::userModel()::query()->cursor() as $user) {
            if ($user instanceof Authenticatable && $breakGlassPolicy->isBreakGlassAccount($user)) {
                $this->record('break-glass', 'ok', 'At least one break-glass account can still sign in with a password.');

                return;
            }
        }

        $this->record('break-glass', 'failure', 'OIDC_ONLY is on but no account qualifies as break-glass ('
            .implode(', ', $this->configuredStrings('oidc.break_glass.roles')).' with a confirmed second factor).');
    }

    /**
     * Front-channel logout is opt-in (OIDC Front-Channel Logout 1.0, standards
     * review S3). When it is on, the IdP must append `iss` and `sid` to the
     * URI (FCL §2, `frontchannel_logout_session_required`), or the endpoint
     * refuses every call with 400.
     */
    private function checkFrontChannelLogout(): void
    {
        if (! Config::boolean('oidc.frontchannel_logout.enabled')) {
            return;
        }

        if (! $this->isFrontChannelLogoutReady()) {
            $this->record('front-channel logout', 'failure', 'oidc.frontchannel_logout.enabled is on but the oidc.frontchannel-logout route is not registered.');

            return;
        }

        $this->record('front-channel logout', 'ok', 'Register '.route('oidc.frontchannel-logout')
            .' as the front-channel logout URI with "front-channel logout session required" (frontchannel_logout_session_required), so the IdP sends iss and sid.');
    }

    private function isFrontChannelLogoutReady(): bool
    {
        return Config::boolean('oidc.frontchannel_logout.enabled') && Route::has('oidc.frontchannel-logout');
    }

    /**
     * @return array<string, string>
     */
    private function urisToRegister(ProviderConfigurationData $configuration): array
    {
        return array_filter([
            'redirect_uri' => $configuration->redirectUri,
            'post_logout_redirect_uri' => $configuration->postLogoutRedirectUri,
            'backchannel_logout_uri' => Route::has('oidc.backchannel-logout') ? route('oidc.backchannel-logout') : null,
            'frontchannel_logout_uri' => $this->isFrontChannelLogoutReady() ? route('oidc.frontchannel-logout') : null,
        ], fn (?string $uri): bool => $uri !== null);
    }

    /**
     * Sets or replaces the four keys in `.env`; other lines stay untouched.
     * Values with special characters are single-quoted, which phpdotenv reads
     * literally (no escapes, no `${...}` interpolation). A value containing a
     * single quote or a line break cannot be written that way and is refused.
     */
    private function writeEnvironment(): void
    {
        $environmentPath = $this->laravel->environmentFilePath();
        $contents = is_file($environmentPath) ? (string) file_get_contents($environmentPath) : '';
        $values = [
            'OIDC_ENABLED' => 'true',
            'OIDC_ISSUER' => Config::string('oidc.issuer'),
            'OIDC_CLIENT_ID' => Config::string('oidc.client_id'),
            'OIDC_CLIENT_SECRET' => is_string(Config::get('oidc.client_secret')) ? Config::string('oidc.client_secret') : '',
        ];

        foreach ($values as $key => $value) {
            if (preg_match("/['\r\n]/", $value) === 1) {
                $this->record('env', 'failure', "{$key} contains a quote or a line break; write .env by hand.");

                return;
            }
        }

        foreach ($values as $key => $value) {
            $line = $key.'='.(preg_match('/^[\w.:\/-]*$/', $value) === 1 ? $value : "'{$value}'");
            $pattern = '/^'.$key.'=.*$/m';

            $contents = preg_match($pattern, $contents) === 1
                ? (string) preg_replace($pattern, str_replace(['\\', '$'], ['\\\\', '\\$'], $line), $contents)
                : rtrim($contents, "\n").($contents === '' ? '' : "\n").$line."\n";
        }

        file_put_contents($environmentPath, $contents);
        $this->record('env', 'ok', "Wrote OIDC_ENABLED, OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET to {$environmentPath}.");
    }

    private function hasFailure(): bool
    {
        return in_array('failure', array_column($this->results, 'status'), true);
    }

    /**
     * @return list<string>
     */
    private function configuredStrings(string $key): array
    {
        return array_values(array_filter(Config::array($key, []), is_string(...)));
    }

    /**
     * @param  'ok'|'warning'|'failure'  $status
     */
    private function record(string $check, string $status, string $detail): void
    {
        $this->results[] = ['check' => $check, 'status' => $status, 'detail' => $detail];
    }

    /**
     * @param  array<string, string>  $urisToRegister
     */
    private function report(bool $hasFailure, array $urisToRegister): void
    {
        if ($this->option('json')) {
            $this->line(json_encode([
                'ok' => ! $hasFailure,
                'checks' => $this->results,
                'register_at_identity_provider' => $urisToRegister,
                'identity_provider_capabilities' => $this->capabilities,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

            return;
        }

        $this->table(['Check', 'Status', 'Detail'], array_map(
            fn (array $result): array => [$result['check'], strtoupper($result['status']), $result['detail']],
            $this->results,
        ));

        if ($urisToRegister !== []) {
            $this->newLine();
            $this->line('Register at the IdP:');

            foreach ($urisToRegister as $name => $uri) {
                $this->line("  {$name}: {$uri}");
            }
        }

        $hasFailure ? $this->error('The OIDC setup has failures.') : $this->info('The OIDC setup looks good.');
    }
}
