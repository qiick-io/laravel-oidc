<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Config;
use Qiick\Oidc\Contracts\ProviderConfigurationRepositoryContract;
use Qiick\Oidc\Enums\TokenEndpointAuthMethodEnum;
use Qiick\Oidc\Exceptions\OidcNotConfiguredException;

function enableConfiguredProvider(): void
{
    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', ' https://idp.example.com/realms/test ');
    Config::set('oidc.client_id', 'laravel-app');
    Config::set('oidc.client_secret', 'secret');
}

it('is disabled until enabled, issuer and client id are all set', function (): void {
    $repository = app(ProviderConfigurationRepositoryContract::class);

    expect($repository->isEnabled())->toBeFalse();

    Config::set('oidc.enabled', true);
    Config::set('oidc.issuer', 'https://idp.example.com');
    expect($repository->isEnabled())->toBeFalse();

    Config::set('oidc.client_id', 'laravel-app');
    expect($repository->isEnabled())->toBeTrue();
});

it('refuses to build a configuration while disabled', function (): void {
    app(ProviderConfigurationRepositoryContract::class)->configuration();
})->throws(OidcNotConfiguredException::class);

it('builds the configuration with the default callback and openid always first', function (): void {
    enableConfiguredProvider();
    Config::set('oidc.scopes', ['profile', 'email', 'qiick.orgs', 'openid', '']);

    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();

    expect($configuration->issuer)->toBe('https://idp.example.com/realms/test')
        ->and($configuration->redirectUri)->toBe('http://localhost/auth/oidc/callback')
        ->and($configuration->scopes)->toBe(['openid', 'profile', 'email', 'qiick.orgs'])
        ->and($configuration->tokenEndpointAuthMethod)->toBe(TokenEndpointAuthMethodEnum::ClientSecretBasic)
        ->and($configuration->isPublicClient())->toBeFalse();
});

it('treats an empty secret as a public client and honours an explicit redirect uri', function (): void {
    enableConfiguredProvider();
    Config::set('oidc.client_secret', '');
    Config::set('oidc.redirect_uri', 'https://app.example.com/sso/callback');
    Config::set('oidc.token_endpoint_auth_method', 'client_secret_post');

    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();

    expect($configuration->isPublicClient())->toBeTrue()
        ->and($configuration->redirectUri)->toBe('https://app.example.com/sso/callback')
        ->and($configuration->tokenEndpointAuthMethod)->toBe(TokenEndpointAuthMethodEnum::ClientSecretPost);
});

it('keeps the scopes a list when a duplicate openid sits in the middle', function (): void {
    enableConfiguredProvider();
    Config::set('oidc.scopes', ['profile', 'openid', 'email']);

    expect(app(ProviderConfigurationRepositoryContract::class)->configuration()->scopes)->toBe(['openid', 'profile', 'email']);
});

it('reads max_age as whole seconds from config or env', function (mixed $configuredMaxAge, ?int $maxAge): void {
    enableConfiguredProvider();
    Config::set('oidc.mfa.max_age', $configuredMaxAge);

    expect(app(ProviderConfigurationRepositoryContract::class)->configuration()->maxAge)->toBe($maxAge);
})->with([
    'unset' => [null, null],
    'integer' => [300, 300],
    'zero' => [0, 0],
    'env string' => ['300', 300],
    'negative' => [-1, null],
    'negative string' => ['-5', null],
    'not a number' => ['soon', null],
]);

it('treats a blank secret as no secret and trims the configured values', function (): void {
    enableConfiguredProvider();
    Config::set('oidc.client_secret', '   ');
    Config::set('oidc.client_id', ' laravel-app ');

    $configuration = app(ProviderConfigurationRepositoryContract::class)->configuration();

    expect($configuration->clientSecret)->toBeNull()
        ->and($configuration->clientId)->toBe('laravel-app');
});

it('reads a token endpoint auth method with surrounding spaces and defaults an unknown one', function (string $configuredMethod, TokenEndpointAuthMethodEnum $method): void {
    enableConfiguredProvider();
    Config::set('oidc.token_endpoint_auth_method', $configuredMethod);

    expect(app(ProviderConfigurationRepositoryContract::class)->configuration()->tokenEndpointAuthMethod)->toBe($method);
})->with([
    'spaces' => [' client_secret_post ', TokenEndpointAuthMethodEnum::ClientSecretPost],
    'unknown' => ['private_key_jwt', TokenEndpointAuthMethodEnum::ClientSecretBasic],
    'blank' => ['  ', TokenEndpointAuthMethodEnum::ClientSecretBasic],
]);
