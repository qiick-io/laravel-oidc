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
     * The local accounts that can still sign in with a password in SSO-only
     * mode (`OIDC_ONLY`), so a broken IdP never locks out the owner. A user
     * qualifies with one of `roles` and, when `require_two_factor` is on, a
     * confirmed second factor (Fortify `two_factor_confirmed_at`, or
     * `two_factor_secret` when the app does not confirm 2FA).
     *
     * The password form stays hidden in SSO-only mode; add
     * `?{query_parameter}=1` to the login URL to show it.
     */
    'break_glass' => [

        'roles' => ['super-admin'],

        'require_two_factor' => true,

        'query_parameter' => 'local',

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

        /*
         * Accepted `acr` values that count as MFA (Signaculum: `urn:qiick:loa:mfa`).
         * Password-only Signaculum value is `urn:qiick:loa:pwd` and is not listed here.
         */
        'acr_values' => ['urn:qiick:loa:mfa'],

        /*
         * Sent as `acr_values` on the authorization request to ask the IdP
         * for a stronger login (for example Keycloak step-up or Signaculum
         * `urn:qiick:loa:mfa`). Null sends nothing.
         */
        'request_acr_values' => null,

        /*
         * Sent as `max_age` (seconds) to ask the IdP for a recent login. When
         * it is sent, the id_token must carry `auth_time`, and a login older
         * than max_age plus `id_token.leeway` is refused (OIDC Core 3.1.2.1,
         * 3.1.3.7 step 13). Null sends nothing.
         */
        'max_age' => null,

        /*
         * When the login asked for an `acr` (acr_values or the claims
         * parameter), refuse an id_token whose `acr` is missing or not one of
         * the requested values. Off by default: such a login then only counts
         * as "MFA not proven" and the app's own second factor runs.
         */
        'require_requested_acr' => false,

    ],

    /*
     * Where the IdP sends the browser after RP-initiated logout. Null means
     * the package route `{APP_URL}/auth/oidc/logged-out`, which checks the
     * logout `state` and then redirects to `logout.redirect_to`. It must be
     * registered at the IdP as a post-logout redirect URI (`oidc:configure`
     * prints it). An explicit URI here skips the state check.
     */
    'post_logout_redirect_uri' => null,

    'logout' => [

        /*
         * Where the post-logout return route sends the browser. Taken from
         * config only, never from the request.
         */
        'redirect_to' => '/',

    ],

    /*
     * Fetch the userinfo endpoint after the code exchange and merge its claims
     * under the id_token claims (the signed id_token wins on any conflict).
     * Turn off for an IdP that puts every claim in the id_token.
     */
    'userinfo' => true,

    /*
     * The package registers its routes under this prefix: `GET {prefix}/redirect`,
     * `GET {prefix}/callback`, `POST {prefix}/backchannel-logout` and (when
     * enabled) `GET {prefix}/frontchannel-logout`. The path matches the routes
     * Externa and Excubia App already use.
     */
    'routes' => [

        'enabled' => true,

        'prefix' => 'auth/oidc',

        /*
         * Middleware of the redirect and callback routes. Logout endpoints
         * never get a session or CSRF middleware.
         */
        'middleware' => ['web', 'guest'],

        /*
         * Named package routes the app registers itself (for example
         * ['oidc.callback']). Every other package route still registers (S4).
         */
        'except' => [],

    ],

    'backchannel_logout' => [

        /*
         * How long a back-channel logout is remembered, in seconds. It must
         * cover the longest local session. Null uses `session.lifetime`.
         */
        'revocation_ttl' => null,

    ],

    /*
     * Front-channel logout (OIDC Front-Channel Logout 1.0). Off by default:
     * back-channel covers server sessions; turn on only when the IdP is
     * registered with frontchannel_logout_session_required (S3).
     */
    'frontchannel_logout' => [

        'enabled' => (bool) env('OIDC_FRONTCHANNEL_LOGOUT', false),

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

        /*
         * Per-hop timeout for IdP calls (seconds). `0` means no practical limit
         * (mapped to a 24h ceiling so outbound's ≥1s contract still holds).
         */
        'timeout' => (int) env('OIDC_HTTP_TIMEOUT', 10),

        /*
         * TCP connect timeout for IdP calls (seconds). `0` means no practical
         * limit (same ceiling as timeout). Defaults to 10s as before.
         */
        'connect_timeout' => (int) env('OIDC_HTTP_CONNECT_TIMEOUT', 10),

        /*
         * Cap on IdP response bodies (discovery, JWKS, token, userinfo).
         * Enforced by qiick/laravel-outbound's PinnedHttpClient.
         */
        'max_response_bytes' => (int) env('OIDC_MAX_RESPONSE_BYTES', 1_048_576),

        /*
         * Docker and lab setups where the app reaches the IdP under another
         * host than the browser does. `discovery_base` replaces the issuer
         * when fetching discovery; `server_origin` replaces the scheme and
         * host of the endpoints the server calls (token, userinfo, JWKS).
         */
        'discovery_base' => env('OIDC_DISCOVERY_BASE'),

        'server_origin' => env('OIDC_SERVER_ORIGIN'),

        /*
         * Mapped onto qiick/laravel-outbound UrlGuardOptions: when true, private
         * / loopback / link-local hosts and plain http are allowed together.
         * Cloud metadata hosts stay blocked either way. Prefer the OIDC key
         * over OUTBOUND_ALLOW_PRIVATE_HOSTS for this package.
         */
        'allow_private_hosts' => (bool) env('OIDC_ALLOW_PRIVATE_HOSTS', false),

    ],

];
