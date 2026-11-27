<?php

declare(strict_types=1);

use Qiick\Oidc\Enums\LoginRefusalReasonEnum;

it('keeps the public reason codes and default login refusal messages', function (): void {
    $messagesByReason = [];

    foreach (LoginRefusalReasonEnum::cases() as $reason) {
        $messagesByReason[$reason->value] = $reason->message();
    }

    expect($messagesByReason)->toEqual([
        'no_linked_user' => 'No local account matches this SSO login. Ask an admin to create your user first.',
        'account_not_linked' => 'An account with this email exists but is not linked to SSO. Ask an admin to link it.',
        'linked_to_another_identity' => 'This account is already linked to a different SSO identity.',
        'email_missing' => 'SSO login failed: missing email claim.',
        'email_not_released' => 'SSO login failed: the identity provider did not share an email address. Ask an admin to check the SSO settings.',
        'email_not_verified' => 'SSO login requires a verified email from the identity provider.',
        'domain_not_allowed' => 'Registration is restricted to allowed email domains.',
        'inactive_user' => 'This account is inactive.',
    ]);
});
