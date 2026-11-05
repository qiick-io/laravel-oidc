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

    /*
     * Where the IdP sends the browser back. Null means `{APP_URL}/auth/oidc/callback`,
     * the path Externa and Excubia App already register at their IdPs.
     */
    'redirect_uri' => null,

    /*
     * Scopes requested on login. `openid` is always sent. Add provider
     * specific scopes here, for example `qiick.orgs` for Signaculum's
     * organisation and role claims.
     */
    'scopes' => ['openid', 'profile', 'email'],

    /*
     * How a confidential client authenticates at the token endpoint:
     * `client_secret_basic` (the OIDC default) or `client_secret_post`.
     * A client without a secret is a public client and sends only its id.
     */
    'token_endpoint_auth_method' => 'client_secret_basic',

    'id_token' => [

        /*
         * Signing algorithms accepted for the id_token. Asymmetric only:
         * `none` and the HS* family are never accepted.
         */
        'algorithms' => ['RS256'],

        /*
         * Clock skew tolerated on `exp`, `iat` and `nbf`, in seconds.
         */
        'leeway' => 60,

        /*
         * Audiences besides the client id that may appear in `aud`. OIDC Core
         * 3.1.3.7 rejects a token with an untrusted extra audience.
         */
        'trusted_audiences' => [],

    ],

    'cache' => [

        /*
         * Cache store for discovery and JWKS. Null uses the default store.
         */
        'store' => null,

        'discovery_ttl' => 21600,

        'jwks_ttl' => 3600,

        /*
         * Minimum seconds between two JWKS refetches triggered by an unknown
         * `kid`, so forged tokens cannot make the app hammer the IdP.
         */
        'jwks_refetch_cooldown' => 30,

    ],

    'http' => [

        'timeout' => 10,

        /*
         * Docker and lab setups where the app reaches the IdP under another
         * host than the browser does. `discovery_base` replaces the issuer
         * when fetching discovery; `server_origin` replaces the scheme and
         * host of the endpoints the server calls (token, userinfo, JWKS).
         */
        'discovery_base' => env('OIDC_DISCOVERY_BASE'),

        'server_origin' => env('OIDC_SERVER_ORIGIN'),

        /*
         * The SSRF guard refuses private, loopback and link-local hosts and
         * plain http. Turn this on only for an IdP on a private network or
         * in local QA. Cloud metadata hosts stay blocked either way.
         */
        'allow_private_hosts' => (bool) env('OIDC_ALLOW_PRIVATE_HOSTS', false),

    ],

];
