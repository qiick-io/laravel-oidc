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
