<?php

declare(strict_types=1);

/*
 * qiick/laravel-oidc configuration.
 *
 * Every value here is a default. An app that keeps its OIDC settings in the
 * database (Externa, Excubia App) overrides them at runtime; the env vars are
 * for automated and agent-driven setups. The names follow the accepted
 * Signaculum SSO design (2026-11-05), section 4 "Configuration".
 */
return [

    /*
     * Turns the SSO login on. Off by default: every qiick app works fully
     * standalone with local login.
     */
    'enabled' => (bool) env('OIDC_ENABLED', false),

    /*
     * The issuer identifier, exactly as the IdP publishes it in its discovery
     * document and in the `iss` claim (no trailing slash added or removed).
     */
    'issuer' => env('OIDC_ISSUER'),

    'client_id' => env('OIDC_CLIENT_ID'),

    /*
     * Null for a public client (PKCE only). Never commit a real secret.
     */
    'client_secret' => env('OIDC_CLIENT_SECRET'),

    /*
     * Text of the SSO button on the login page. Null lets the app pick its
     * own default ("Sign in with SSO").
     */
    'button_label' => env('OIDC_BUTTON_LABEL'),

    /*
     * Just-in-time provisioning: create a local user on the first SSO login.
     * Off by default.
     */
    'jit' => (bool) env('OIDC_JIT', false),

    /*
     * Link an SSO identity to an existing local user with the same verified
     * email. Off by default: turn it on only for an IdP that does not let
     * users choose an arbitrary email, or it becomes an account takeover path.
     */
    'auto_link' => (bool) env('OIDC_AUTO_LINK', false),

    /*
     * SSO-only mode: hide the password form. A local break-glass admin can
     * always sign in with password and 2FA, so a broken IdP never locks out
     * the owner.
     */
    'only' => (bool) env('OIDC_ONLY', false),

];
