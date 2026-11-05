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
     * JIT provisioning only for these email domains (for example
     * ['example.com']). Empty allows every domain.
     */
    'allowed_domains' => [],

    /*
     * Auto-link and JIT need `email_verified: true` from the IdP. Microsoft
     * Entra ID sends no `email_verified` claim; turn this off only for an IdP
     * whose emails are verified by the organisation (never for an IdP where
     * users pick their own address). Logins of already linked users never
     * depend on the email.
     */
    'require_verified_email' => true,

    /*
     * Use Laravel's "remember me" cookie for SSO logins. Off by default: the
     * IdP session is the long-lived one, and a remember cookie would outlive
     * a back-channel logout.
     */
    'remember' => false,

    /*
     * Where the user lands after an SSO login (`redirect()->intended()`), and
     * where a failed SSO login sends the user, with the message in the
     * `email` error bag key.
     */
    'home' => '/',

    'login_url' => '/login',

    'users' => [

        /*
         * The Eloquent user model. Null uses `auth.providers.users.model`.
         */
        'model' => null,

        'table' => 'users',

        'email_column' => 'email',

        /*
         * A boolean column; users with false there cannot sign in through
         * SSO. Null when the app has no such column. Externa and Excubia App
         * use `is_active`.
         */
        'active_column' => null,

    ],

    /*
     * Role mapping, run at every SSO login before the user is signed in.
     * Off by default. The IdP can only grant and revoke the app roles listed
     * as values of `map`; every other local role is left alone, and
     * `super-admin` can never be granted (break-glass stays local).
     *
     * Signaculum (`qiick.orgs` scope) sends `orgs: [{id, slug, roles: [...]}]`:
     * set `claim` to `orgs` and `organization` to the id or slug of the org
     * this app belongs to. Other IdPs send a flat list of role or group names,
     * for example Keycloak `realm_access.roles` or Entra ID `roles`: set
     * `claim` to that path and leave `organization` null.
     *
     * Without the claim in the login, local roles stay as they are.
     */
    'roles' => [

        'enabled' => false,

        'claim' => 'orgs',

        'organization' => null,

        /*
         * IdP role => app role, or a list of app roles. For example Externa:
         * ['owner' => 'admin', 'admin' => 'admin', 'member' => 'editor'].
         */
        'map' => [],

        /*
         * App roles the mapping may never grant, on top of `super-admin`.
         */
        'forbidden' => [],

    ],

    /*
     * Second factor. When the app requires 2FA for a user, an SSO login counts
     * only if the IdP says MFA happened: an `amr` value (RFC 8176) in
     * `amr_values`, or an `acr` in `acr_values`. Otherwise the app runs its
     * own TOTP or passkey challenge after the callback (Laravel Fortify is
     * supported out of the box). Apps bind SecondFactorChallengeContract to
     * read their own "2FA required" setting; `required` is the default.
     */
    'mfa' => [

        'required' => false,

        'amr_values' => ['mfa'],

        'acr_values' => [],

        /*
         * Sent as `acr_values` on the authorization request to ask the IdP
         * for a stronger login (for example Keycloak step-up). Null sends
         * nothing.
         */
        'request_acr_values' => null,

    ],

    /*
     * Where the IdP sends the browser after RP-initiated logout. Null means
     * `{APP_URL}/`. It must be registered at the IdP as a post-logout
     * redirect URI, or the IdP shows its own confirmation page instead.
     */
    'post_logout_redirect_uri' => null,

    /*
     * Fetch the userinfo endpoint after the code exchange and merge its claims
     * under the id_token claims (the signed id_token wins on any conflict).
     * Turn off for an IdP that puts every claim in the id_token.
     */
    'userinfo' => true,

    /*
     * The package registers its routes under this prefix: `GET {prefix}/redirect`,
     * `GET {prefix}/callback` and `POST {prefix}/backchannel-logout`. The path
     * matches the routes Externa and Excubia App already use.
     */
    'routes' => [

        'enabled' => true,

        'prefix' => 'auth/oidc',

        /*
         * Middleware of the redirect and callback routes. The back-channel
         * logout route never gets a session or CSRF middleware.
         */
        'middleware' => ['web', 'guest'],

    ],

    'backchannel_logout' => [

        /*
         * How long a back-channel logout is remembered, in seconds. It must
         * cover the longest local session. Null uses `session.lifetime`.
         */
        'revocation_ttl' => null,

    ],

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
