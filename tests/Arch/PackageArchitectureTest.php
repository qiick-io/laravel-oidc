<?php

declare(strict_types=1);

/**
 * Package-only architecture rules. Naming, suffixes, strict types and readonly
 * DTOs are the shared qiick rules in NamingArchitectureTest.php (configured in
 * naming-architecture.php).
 */
arch('the Laravel namespace only holds the service provider')
    ->expect('Qiick\Oidc\Laravel')
    ->toHaveSuffix('ServiceProvider');

arch('enums are enums')
    ->expect('Qiick\Oidc\Enums')
    ->toBeEnums();

arch('exceptions share one base class')
    ->expect('Qiick\Oidc\Exceptions')
    ->toExtend('Qiick\Oidc\Exceptions\OidcException')
    ->ignoring('Qiick\Oidc\Exceptions\OidcException');

arch('test doubles shipped for apps start with Fake')
    ->expect('Qiick\Oidc\Testing')
    ->toHavePrefix('Fake');

arch('only the test doubles use the Http facade directly')
    ->expect('Illuminate\Support\Facades\Http')
    ->toOnlyBeUsedIn('Qiick\Oidc\Testing');

arch('events are readonly')
    ->expect('Qiick\Oidc\Events')
    ->toBeReadonly();

it('declares the Illuminate components imported by package code as runtime requirements', function (): void {
    $packageRoot = dirname(__DIR__, 2);
    $manifest = json_decode((string) file_get_contents($packageRoot.'/composer.json'), true, flags: JSON_THROW_ON_ERROR);
    $components = [];

    foreach (['src', 'routes', 'config', 'database'] as $directory) {
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($packageRoot.'/'.$directory, FilesystemIterator::SKIP_DOTS));

        foreach ($files as $file) {
            if ($file->getExtension() === 'php') {
                preg_match_all('/^use Illuminate\\\\([A-Z][A-Za-z]+)\\\\/m', (string) file_get_contents($file->getPathname()), $matches);
                array_push($components, ...$matches[1]);
            }
        }
    }

    // Foundation belongs to the Laravel host application and has no split component.
    $componentNames = array_diff(array_unique($components), ['Foundation']);
    $requiredPackages = array_map(fn (string $component): string => 'illuminate/'.strtolower($component), $componentNames);

    expect($requiredPackages)->not->toBeEmpty();
    expect(array_values(array_diff($requiredPackages, array_keys($manifest['require']))))->toBe([]);
});

/**
 * docs/PUBLIC-API.md freezes the public API at 1.0: every class in src/ is
 * either named there (by its short name, or by a pattern such as
 * `Console\*Command`) or marked @internal, so a new class has to be placed
 * on one side on purpose.
 */
it('names every class in the public API list or marks it internal', function (): void {
    $publicApi = (string) file_get_contents(__DIR__.'/../../docs/PUBLIC-API.md');
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

/**
 * A method with executable statements puts its class in the mutation
 * inventory, including an enum or data class that gains behaviour.
 */
it('keeps every class with code in the mutation gate', function (): void {
    preg_match_all("/^  '(Qiick\\\\Oidc\\\\[^']+)'$/m", (string) file_get_contents(__DIR__.'/../../scripts/mutate-per-class.sh'), $matches);
    $gatedClasses = $matches[1];

    $hasExecutableMethod = static function (string $source): bool {
        $tokens = array_values(array_filter(PhpToken::tokenize($source), fn (PhpToken $token): bool => ! $token->isIgnorable()));
        $isInSignature = false;

        foreach ($tokens as $position => $token) {
            if ($token->is(T_FUNCTION)) {
                $isInSignature = true;
            }

            if ($isInSignature && $token->is(['{', ';'])) {
                if ($token->is('{') && ! $tokens[$position + 1]->is('}')) {
                    return true;
                }

                $isInSignature = false;
            }
        }

        return false;
    };
    $sourceDirectory = (string) realpath(__DIR__.'/../../src');
    $executableClasses = [];

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($sourceDirectory, FilesystemIterator::SKIP_DOTS)) as $sourceFile) {
        if ($sourceFile->getExtension() === 'php' && $hasExecutableMethod((string) file_get_contents($sourceFile->getPathname()))) {
            $relativePath = substr($sourceFile->getPathname(), strlen($sourceDirectory) + 1);
            $executableClasses[] = 'Qiick\Oidc\\'.str_replace(['/', '.php'], ['\\', ''], $relativePath);
        }
    }

    sort($executableClasses);
    sort($gatedClasses);

    expect($gatedClasses)->toBe($executableClasses);
});
