<?php

declare(strict_types=1);

namespace Qiick\Oidc\Enums;

/**
 * Why an SSO identity could not be mapped to a local user. Apps can switch on
 * it to show their own (translated) message.
 */
enum LoginRefusalReasonEnum: string
{
    case NoLinkedUser = 'no_linked_user';
    case AccountNotLinked = 'account_not_linked';
    case LinkedToAnotherIdentity = 'linked_to_another_identity';
    case EmailMissing = 'email_missing';
    case EmailNotReleased = 'email_not_released';
    case EmailNotVerified = 'email_not_verified';
    case DomainNotAllowed = 'domain_not_allowed';
    case InactiveUser = 'inactive_user';
    case SecondFactorUnavailable = 'second_factor_unavailable';

    /**
     * English default message, safe to show to the user. Wording follows
     * Externa's current SSO messages so the migration keeps its translations.
     */
    public function message(): string
    {
        return match ($this) {
            self::NoLinkedUser => 'No local account matches this SSO login. Ask an admin to create your user first.',
            self::AccountNotLinked => 'An account with this email exists but is not linked to SSO. Ask an admin to link it.',
            self::LinkedToAnotherIdentity => 'This account is already linked to a different SSO identity.',
            self::EmailMissing => 'SSO login failed: missing email claim.',
            self::EmailNotReleased => 'SSO login failed: the identity provider did not share an email address. Ask an admin to check the SSO settings.',
            self::EmailNotVerified => 'SSO login requires a verified email from the identity provider.',
            self::DomainNotAllowed => 'Registration is restricted to allowed email domains.',
            self::InactiveUser => 'This account is inactive.',
            self::SecondFactorUnavailable => 'A required second factor could not be started. Contact your administrator.',
        };
    }
}
