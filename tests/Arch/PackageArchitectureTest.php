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

/**
 * Every class in src/ is either in the per-class mutation gate
 * (scripts/mutate-per-class.sh) or listed here as having nothing to mutate,
 * so a new class cannot silently stay out of the gate. Interfaces have no
 * code and are skipped.
 */
it('keeps every class with code in the mutation gate', function (): void {
    $classesWithoutMutations = [
        // Only promoted constructor properties or cases: pest --mutate creates no mutant.
        'Qiick\Oidc\Data\LogoutTokenData',
        'Qiick\Oidc\Data\OidcOutboundStackData',
        'Qiick\Oidc\Enums\LoginRefusalReasonEnum',
        'Qiick\Oidc\Enums\TokenEndpointAuthMethodEnum',
        'Qiick\Oidc\Erasure\OrganisationScopeUnsupportedException',
        'Qiick\Oidc\Events\OidcIdentityLinkedEvent',
        'Qiick\Oidc\Events\OidcLoginSucceededEvent',
        'Qiick\Oidc\Events\OidcLogoutReceivedEvent',
        'Qiick\Oidc\Events\OidcUserProvisionedEvent',
        'Qiick\Oidc\Events\SubjectErasedEvent',
        'Qiick\Oidc\Exceptions\IdentityProviderRequestException',
        'Qiick\Oidc\Exceptions\InvalidCallbackException',
        'Qiick\Oidc\Exceptions\InvalidTokenException',
        'Qiick\Oidc\Exceptions\OidcException',
        'Qiick\Oidc\Exceptions\OidcNotConfiguredException',
        'Qiick\Oidc\Services\NullUserClaimSynchronizationService',
    ];

    preg_match_all("/^  '(Qiick\\\\Oidc\\\\[^']+)'$/m", (string) file_get_contents(__DIR__.'/../../scripts/mutate-per-class.sh'), $matches);
    $gatedClasses = $matches[1];

    $sourceDirectory = realpath(__DIR__.'/../../src');
    $sourceClasses = [];

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($sourceDirectory, FilesystemIterator::SKIP_DOTS)) as $sourceFile) {
        $className = 'Qiick\Oidc\\'.str_replace(['/', '.php'], ['\\', ''], substr($sourceFile->getPathname(), strlen($sourceDirectory) + 1));

        if (! interface_exists($className)) {
            $sourceClasses[] = $className;
        }
    }

    sort($sourceClasses);
    $expectedClasses = [...$gatedClasses, ...$classesWithoutMutations];
    sort($expectedClasses);

    expect($expectedClasses)->toBe($sourceClasses);
});
