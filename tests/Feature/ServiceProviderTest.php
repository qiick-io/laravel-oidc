<?php

declare(strict_types=1);

it('merges the package defaults into the oidc config', function (): void {
    expect(config('oidc'))->toMatchArray([
        'enabled' => false,
        'issuer' => null,
        'client_id' => null,
        'client_secret' => null,
        'button_label' => null,
        'jit' => false,
        'auto_link' => false,
        'only' => false,
    ]);
});

it('lets an app publish the config file', function (): void {
    $this->artisan('vendor:publish', ['--tag' => 'oidc-config', '--force' => true])
        ->assertSuccessful();

    expect(config_path('oidc.php'))->toBeFile();

    unlink(config_path('oidc.php'));
});
