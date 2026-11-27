<?php

declare(strict_types=1);

use Illuminate\Routing\Route;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Route as RouteFacade;
use Qiick\Oidc\Tests\Support\PackageTestCase;

pest()->extend(PackageTestCase::class);

/**
 * docs/public-api.md freezes the public API at 1.0: every class in src/ is
 * either named there (by its short name, or by a pattern such as
 * `Console\*Command`) or marked @internal, so a new class has to be placed
 * on one side on purpose.
 */
it('names every class in the public API list or marks it internal', function (): void {
    $publicApi = (string) file_get_contents(__DIR__.'/../../docs/public-api.md');
    preg_match_all('/`([A-Za-z\\\\]*\*[A-Za-z]*)`/', $publicApi, $patternMatches);
    $listedPatterns = array_map(
        fn (string $pattern): string => '/^'.str_replace('\\*', '[A-Za-z]+', preg_quote($pattern, '/')).'$/',
        $patternMatches[1],
    );
    $sourceDirectory = (string) realpath(__DIR__.'/../../src');
    $unclassifiedClasses = [];

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($sourceDirectory, FilesystemIterator::SKIP_DOTS)) as $sourceFile) {
        $relativeName = str_replace(['/', '.php'], ['\\', ''], substr($sourceFile->getPathname(), strlen($sourceDirectory) + 1));
        $shortName = basename($sourceFile->getPathname(), '.php');
        $isInternal = str_contains((string) file_get_contents($sourceFile->getPathname()), '@internal Not part of the public API');
        $isListed = str_contains($publicApi, $shortName)
            || array_filter($listedPatterns, fn (string $pattern): bool => preg_match($pattern, $relativeName) === 1) !== [];

        if (! $isInternal && ! $isListed) {
            $unclassifiedClasses[] = $relativeName;
        }
    }

    expect($unclassifiedClasses)->toBe([]);
});

it('lists every shipped config key and environment variable in the public API', function (): void {
    $publicApi = (string) file_get_contents(__DIR__.'/../../docs/public-api.md');
    $configPath = __DIR__.'/../../config/oidc.php';
    $configuration = require $configPath;
    $leafKeys = array_keys(Arr::dot($configuration));
    // A list such as scopes is one public key. Its default entries are values.
    $settingKeys = array_unique(preg_replace('/\.\d+(?:\..*)?$/', '', $leafKeys) ?? []);
    preg_match_all("/\benv\('([^']+)'/", (string) file_get_contents($configPath), $matches);

    expect($settingKeys)->not->toBeEmpty()
        ->and($matches[1])->not->toBeEmpty();

    foreach ([...$settingKeys, ...$matches[1]] as $name) {
        expect($publicApi)->toContain("`{$name}`");
    }
});

it('lists the method and default URI of every package route in the public API', function (): void {
    $publicApi = (string) file_get_contents(__DIR__.'/../../docs/public-api.md');
    $routes = collect(RouteFacade::getRoutes()->getRoutes())
        ->filter(fn (Route $route): bool => str_starts_with($route->getName() ?? '', 'oidc.'));

    expect($routes)->not->toBeEmpty();

    foreach ($routes as $route) {
        foreach (array_diff($route->methods(), ['HEAD']) as $method) {
            expect($publicApi)->toContain("| `{$route->getName()}` | `{$method}` | `/{$route->uri()}` |");
        }
    }
});
