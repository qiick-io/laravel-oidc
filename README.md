<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/header-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset=".github/assets/header-light.svg">
    <img alt="laravel-oidc: OpenID Connect client for Laravel" src=".github/assets/header-light.svg" width="100%">
  </picture>
</p>

# laravel-oidc

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![PHP](https://img.shields.io/badge/PHP-%5E8.3-777BB4?logo=php&logoColor=white)](./composer.json)
[![Laravel](https://img.shields.io/badge/Laravel-12%20%7C%2013-FF2D20?logo=laravel&logoColor=white)](./composer.json)
[![Version](https://img.shields.io/badge/version-1.0.0--beta.8-orange.svg)](./CHANGELOG.md)

> **Status:** `1.0.0-beta.8`. Pre-release: APIs and config may still change before `1.0.0`. See [CHANGELOG](./CHANGELOG.md) Upgrade notes. The public API that `1.0.0` freezes, and the deprecation policy after it, are in [`docs/PUBLIC-API.md`](./docs/PUBLIC-API.md).

`qiick/laravel-oidc` is an OpenID Connect client for Laravel apps: PKCE, `id_token` validation, logout, role mapping. It works with any standard identity provider: Keycloak, Zitadel, Authentik, Microsoft Entra ID, Google Workspace or Signaculum. It is the shared SSO login of the [qiick](https://qiick.io) apps and replaces the OIDC client that Externa and Excubia App each carry today.

SSO is optional. An app that installs the package keeps its local login (email and password, 2FA, passkeys), and SSO stays off until it is configured.

## Requirements

- PHP 8.3, 8.4 or 8.5 (`^8.3` in `composer.json`)
- Laravel 12 or 13 (`illuminate/*` `^12.0 || ^13.0`)

CI runs Pest on every cell of PHP 8.3/8.4/8.5 × Laravel 12/13 × lowest/stable, plus end-to-end jobs against Keycloak 26, Signaculum and Zitadel.

## Installation

```bash
composer require qiick/laravel-oidc
php artisan vendor:publish --tag=oidc-config
php artisan migrate   # user_identities and oidc_logout_revocations
php artisan oidc:configure --issuer=https://idp.example.com/realms/acme --client-id=my-app --client-secret=...
```

`oidc:configure` checks the setup against the IdP without a browser:
- settings, discovery (exact issuer, code flow, PKCE `S256`), end-session support;
- the capabilities the IdP advertises: back-channel logout with `sid`, front-channel logout with `iss` and `sid` (when it is on), and the requested `acr` values against `acr_values_supported`. These are warnings only; `--json` lists them under `identity_provider_capabilities` (`frontchannel_logout_supported`, `frontchannel_logout_session_supported`, `backchannel_logout_supported`, `backchannel_logout_session_supported`, `acr_values_supported`, `claims_parameter_supported`) for a settings UI;
- signing algorithms and JWKS keys, client type, redirect URI;
- that `app.timezone` is `UTC` (a warning otherwise, see "Timestamps are UTC");
- that the cache store can make each login `state` single-use (a failure for the array driver outside tests);
- when front-channel logout is on, that its route is registered;
- in SSO-only mode, that a break-glass account exists.

It prints the URIs to register at the IdP: the redirect URI, the post-logout redirect URI and the back-channel logout URI, plus the front-channel logout URI when front-channel logout is on. `--json` prints a machine-readable report for agents. `--write-env` writes `OIDC_ENABLED`, `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` to `.env`, only when every check passed. The exit code is `0` without failures. The client secret is never printed.

Apps that use [Laravel Boost](https://github.com/laravel/boost) also get the package's agent guidelines (`resources/boost/guidelines/core.blade.php`).

## Configuration

Every key in `config/oidc.php` has an env var. They are defaults: an app can override them at runtime from its own settings (for example a settings table edited in an admin UI).

| Env var | Config key | Default | Meaning |
| --- | --- | --- | --- |
| `OIDC_ENABLED` | `oidc.enabled` | `false` | Turns the SSO login on. |
| `OIDC_ISSUER` | `oidc.issuer` | `null` | Issuer identifier, exactly as in the IdP's discovery document. |
| `OIDC_CLIENT_ID` | `oidc.client_id` | `null` | Client id registered at the IdP. |
| `OIDC_CLIENT_SECRET` | `oidc.client_secret` | `null` | Client secret; `null` for a public client (PKCE only). |
| `OIDC_BUTTON_LABEL` | `oidc.button_label` | `null` | Text of the SSO button on the login page. |
| `OIDC_JIT` | `oidc.jit` | `false` | Create a local user on the first SSO login. |
| `OIDC_AUTO_LINK` | `oidc.auto_link` | `false` | Link to an existing local user with the same verified email. **Off by default** (Decision Luca, 2026-11-13); turn on only for a trusted IdP. |
| `OIDC_ONLY` | `oidc.only` | `false` | SSO-only mode: hide the password form; a break-glass local admin still works. |

### Security-relevant defaults (decided in v1.0.0-beta.1, unchanged since)

| Topic | Default | Notes |
| --- | --- | --- |
| Auto-link (`oidc.auto_link`) | **off** | Opt in per provider. Existing Externa/Excubia installs that always auto-linked must set `OIDC_AUTO_LINK=true` (or their settings UI) after migration if they still need email linking. |
| Verified email (`oidc.require_verified_email`) | **on** | Auto-link and JIT need `email_verified: true`. Per-provider opt-out for IdPs that never send the claim (Entra ID). |
| Remember-me for SSO (`oidc.remember`) | **off** | A remember cookie would outlive the IdP session and a back-channel logout. |
| 2FA after SSO | App challenge when `id_token` lacks accepted `amr` / `acr` | See “Second factor (MFA)” below; release notes must say SSO does not skip the app's 2FA. |

### Timestamps are UTC

The package's tables store times without a time zone: `timestamp` columns for past events (`user_identities.last_login_at`, `last_auth_time_at`, `oidc_logout_revocations.received_at` and every `created_at` / `updated_at`) and a `dateTime` column for the future pruning date (`oidc_logout_revocations.expires_at`). Laravel writes and reads them in `app.timezone`, so the package expects `app.timezone` to be `UTC`, as in Externa and Excubia App. With another time zone the stored values are local times, and comparisons with the IdP's epoch claims (`auth_time`, `exp`) and between app servers become ambiguous. `oidc:configure` warns when `app.timezone` is not `UTC`.

## Protocol profile

What the package implements, from the accepted Signaculum SSO design (2026-11-05):

- **Flow:** authorization code with PKCE `S256` only, also for confidential clients. `state` and `nonce` on every login; each `state` is single-use, consumed with an atomic add on `oidc.cache.store`, so two parallel callbacks on one session cannot both pass (a cache that does not answer refuses the login). No implicit flow, no password grant.
- **`id_token`:** signed `RS256` by default; `RS384`, `RS512`, `ES256`, `ES384` and `PS256` can be enabled in `oidc.id_token.algorithms`. Validated on every login: signature through the JWKS (cached, refetched on an unknown `kid`; RSA keys of at least 2048 bits, EC keys only on the curve of their algorithm, `key_ops` honoured, a `kid` published twice refused; PS256 with a salt as long as the hash), no `crit` header, `iss`, `aud` (a string or a list of strings), `exp`, `iat`, `nonce`, `azp` when present, and `at_hash` against the access token when present (OIDC Core 3.1.3.8).
- **Session:** after the callback the app keeps its own Laravel session, regenerated. The session remembers the issuer, `sub`, `sid`, `acr`, `amr`, `auth_time` and the `id_token` (for logout) in a versioned payload; an unknown version ends the session. The `id_token` is stored encrypted with the app key (`Crypt`), so a database session row never holds the raw JWT (a session written by beta.6 is re-encrypted on its first read); a stored token that does not decrypt (a rotated `APP_KEY` without `APP_PREVIOUS_KEYS`, tampering) ends the session. Access and refresh tokens are not stored.
- **Logout:** RP-initiated logout (`end_session_endpoint`, `id_token_hint`, `post_logout_redirect_uri`), back-channel logout (signed `logout_token`, matched by `sid` / `sub`) and, behind `oidc.frontchannel_logout.enabled` (off by default), front-channel logout (`iss` + `sid` in an IdP iframe). Revocations are stored durably in `oidc_logout_revocations`.
- **Claims:** `sub`, `email`, `email_verified`, `name`, `given_name`, `family_name`, `preferred_username`, `picture`, `locale`, `amr` / `acr`. Provider-specific claims, such as an `orgs` claim for roles, are read through config, never hard-coded.
- **Identity key:** the pair (`issuer`, `sub`), stored in a `user_identities` table and compared byte for byte on every database (binary collation on MySQL and MariaDB). A `sub` with leading or trailing whitespace is refused.

## Usage

```bash
php artisan migrate   # creates user_identities and oidc_logout_revocations
```

The package registers these routes under `oidc.routes.prefix` (`auth/oidc`). An app that registers one of them itself lists its name in `oidc.routes.except` and still gets the others; `oidc.routes.enabled = false` turns all of them off.

| Route | Name | Middleware | Purpose |
| --- | --- | --- | --- |
| `GET /auth/oidc/redirect` | `oidc.redirect` | `web`, `guest` | The SSO button: sends the browser to the IdP. |
| `GET /auth/oidc/callback` | `oidc.callback` | `web`, `guest` | The redirect URI to register at the IdP. |
| `POST /auth/oidc/backchannel-logout` | `oidc.backchannel-logout` | none | The back-channel logout URI to register at the IdP. The endpoint limits rejected requests per sender IP. |
| `GET /auth/oidc/frontchannel-logout` | `oidc.frontchannel-logout` | `throttle:60,1,oidc-frontchannel-logout:` | The front-channel logout URI; answers 404 unless `oidc.frontchannel_logout.enabled`. |

Point your SSO button at `route('oidc.redirect')`. The callback validates everything (see the protocol profile), finds or creates the local user, logs them in on the default guard, regenerates the session and redirects to `redirect()->intended(config('oidc.home'))`. On failure it redirects to `oidc.login_url` with a message under the `email` key: a refusal says why (inactive user, no linked account, ...), and a protocol or IdP failure shows a generic message and logs the technical one.

### Linking SSO identities to local users

The identity key is (`issuer`, `sub`), stored in `user_identities`. On each login:

1. If (issuer, sub) is already linked, that user signs in. The email does not matter.
2. Otherwise, with `OIDC_AUTO_LINK`, the local user with the same **verified** email is linked, unless that user is already linked to another identity of this issuer. Turn it on only for an IdP where users cannot choose an arbitrary email.
3. Otherwise, with `OIDC_JIT`, a new user is created if the email domain is in `oidc.allowed_domains` (empty allows all). An existing account with that email is never duplicated.
4. Otherwise the login is refused.

Users with `false` in `oidc.users.active_column` (for example `is_active`) are always refused. The default JIT provisioning fills `name` (the `name` claim, else `given_name` + `family_name`), `email`, an unusable random password and `email_verified_at`. Apps with `first_name` / `last_name` columns use `$identity->personName()`: it returns `given_name` / `family_name`, or `name` split with the last word as the family name. Apps with other columns or a default role bind their own provisioning:

```php
$this->app->bind(UserProvisioningContract::class, ProvisionSsoUserService::class);
```

The events `OidcIdentityLinkedEvent`, `OidcUserProvisionedEvent` and `OidcLoginSucceededEvent` carry the user and the identity, for activity logs and role mapping.

### Role mapping

Off by default (`oidc.roles.enabled`). At every SSO login, before the user is signed in, the IdP's roles are mapped to app roles:

```php
'roles' => [
    'enabled' => true,
    'claim' => 'orgs',            // Signaculum with the qiick.orgs scope
    'organization' => 'acme',     // id or slug of the org this app belongs to
    'map' => ['owner' => 'admin', 'admin' => 'admin', 'member' => 'editor'],
    'forbidden' => [],
],
```

- Only the app roles that appear as values of `map` are ever granted or revoked. Every other local role is left alone.
- `super-admin` and the `forbidden` roles are never granted, even when mapped, and never revoked, so the break-glass admin stays local.
- Without the claim in the login, local roles stay as they are. A user missing from the configured organisation loses the mapped roles.
- For an IdP with a flat role or group list, set `claim` to its path (Keycloak `realm_access.roles`, Entra ID `roles`) and leave `organization` null. Zitadel's `urn:zitadel:iam:org:project:roles` map (role name → org ids) is also accepted: the map keys are the role names. When Zitadel asserts project roles it also puts the project id in the id_token `aud`; add that project id to `oidc.id_token.trusted_audiences`.

The default `RoleSynchronizationContract` calls spatie/laravel-permission's `hasRole` / `assignRole` / `removeRole`. A mapped role missing in the app is skipped with a warning.

### Second factor (MFA)

When the app requires 2FA for a user, an SSO login counts only if the signed `id_token` proves MFA: an `amr` value in `oidc.mfa.amr_values` (default `['mfa']`, RFC 8176), or an `acr` in `oidc.mfa.acr_values` (default `['urn:qiick:loa:mfa']`, Signaculum). Signaculum also emits `urn:qiick:loa:pwd` for password-only logins when `acr` was requested; that value is not accepted as MFA. Otherwise the callback hands over to the app's own challenge instead of signing the user in. The challenge must end with `Auth::login()`, and the package then completes the SSO session (identity for logout). `amr` and `acr` are never taken from the unsigned userinfo response. `amr` is always present on Signaculum id_tokens.

The default `SecondFactorChallengeContract` reads `oidc.mfa.required` and starts Laravel Fortify's two-factor challenge (`login.id` / `login.remember` and the `two-factor.login` route) for a user with a confirmed TOTP secret. A user without a second factor is signed in, and the app's own enrollment rules apply, as after a password login. Apps bind their own implementation to read their "2FA required" setting:

```php
$this->app->bind(SecondFactorChallengeContract::class, SsoSecondFactorChallengeService::class);
```

`oidc.mfa.request_acr_values` asks the IdP for a stronger login (`acr_values` on the authorization request). An app can also ask per login, through `AuthorizationCodeFlowService::redirect($request, ['acr_values' => '...'])` or the `claims` parameter (`{"id_token":{"acr":{"essential":true,"values":[...]}}}`). Each pending login remembers what it asked for, and the callback checks the answer:

- `acr` is optional and `acr_values` only a request (OIDC Core 2 and 3.1.2.1), so by default a missing `acr`, or one that is not among the requested values, does not refuse the login: it counts as "MFA not proven", whatever `amr` says, and the app's own second factor runs.
- With `oidc.mfa.require_requested_acr = true`, such a login is refused instead, for apps without their own second factor.
- In the `claims` parameter, `"essential": true` without `values` accepts any `acr` except `"0"` (OIDC Core 2: level 1 not met) but requires one; a voluntary request without values asks for nothing; `values` that are not a non-empty list of strings make nothing acceptable.

`oidc.mfa.max_age` (seconds, null by default) is sent as `max_age` to ask for a recent login; a `max_age` passed to `redirect()` wins over it and must be a whole number of seconds, 0 or more (anything else throws `InvalidArgumentException`). When it is sent, the `id_token` must carry `auth_time` (fractions of a second are dropped), and a login with `now - auth_time > max_age + oidc.id_token.leeway`, or an `auth_time` more than the leeway in the future, is refused (OIDC Core 3.1.2.1 and 3.1.3.7 step 13). Without `max_age`, `auth_time` is optional. An app with its own settings repository passes `maxAge` to `ProviderConfigurationData`.

### SSO-only mode and break-glass

With `OIDC_ONLY=true` the login page shows only the SSO button, and local logins are refused except for break-glass accounts. A break-glass account has one of `oidc.break_glass.roles` (default `super-admin`) and a confirmed second factor (`oidc.break_glass.require_two_factor`). A broken IdP therefore never locks out the owner. The mode is active only while SSO itself is configured, so turning SSO off restores local login for everyone.

- The login page reads `app(SsoOnlyModeService::class)->loginOptions($request)->toArray()`: `isSsoAvailable`, `isSsoOnly`, `isPasswordLoginVisible`, `buttonLabel`, `redirectUrl`. The password form is shown again with `?local=1` (`oidc.break_glass.query_parameter`). Hiding it is only cosmetic; the server enforces the rule.
- Password logins through `Auth::attempt()` are refused by the package (`Validated` event).
- Login callbacks that bypass `attempt()` must ask the package themselves:

```php
Fortify::authenticateUsing(fn (Request $request) => /* ...password check... */ $user !== null && app(SsoOnlyModeService::class)->canUseLocalLogin($user) ? $user : null);
Passkeys::authorizeLoginUsing(fn (Request $request, $user) => /* ... */ app(SsoOnlyModeService::class)->canUseLocalLogin($user));
```

An app with another notion of owner binds `BreakGlassPolicyContract`.

### Using the protocol layer directly

An app with its own routes can call the services:

```php
$identity = app(AuthorizationCodeFlowService::class)->handleCallback($request); // throws an OidcException subclass
$challenge = app(OidcLoginService::class)->login($request, $identity);          // null when signed in, else the 2FA challenge; throws LoginRefusedException
```

`$identity->claims` holds the validated `id_token` claims plus the userinfo claims (`oidc.userinfo`, on by default). The userinfo `sub` must match the `id_token`, and the signed `id_token` wins any conflict.

### Logout

RP-initiated logout ends the IdP session too. Read the URL before invalidating the session, because it needs the stored `id_token`:

```php
$endSessionUrl = app(RpInitiatedLogoutService::class)->endSessionUrl($request->session()); // null for a local login

Auth::logout();
$request->session()->invalidate();
$request->session()->regenerateToken();

return $endSessionUrl !== null ? redirect()->away($endSessionUrl) : redirect('/');
```

By default the IdP sends the browser back to the package route `GET /auth/oidc/logged-out` (`oidc.logged-out`), which `oidc:configure` prints: register it at the IdP as a post-logout redirect URI. `endSessionUrl()` adds a random `state` (RP-Initiated Logout 1.0 §2) and keeps it for ten minutes in an HttpOnly, SameSite=Lax cookie on `/auth/oidc` (Secure over https), because the app invalidates its session before the browser comes back. The route checks the state, forgets the cookie and redirects to `oidc.logout.redirect_to` (default `/`), which comes from config only. A missing or wrong state is logged as a warning and still redirects: the local logout has already happened. An explicit `oidc.post_logout_redirect_uri` (or an app repository that passes its own `postLogoutRedirectUri`) other than the package route skips the state check; one equal to the route keeps it. The route is rate limited (60 requests a minute), since every unmatched state is logged.

### Back-channel logout

The package registers `POST /auth/oidc/backchannel-logout` (route `oidc.backchannel-logout`, no session, no CSRF). Register its absolute URL at the IdP as the back-channel logout URI. The endpoint validates the signed `logout_token` (OIDC Back-Channel Logout 1.0 §2.6): signature, `iss`, `aud`, `exp`, `iat`, the logout `events` member, no `nonce`, a `sub`, a `sid` or both, and a `jti`. It then records the logout in the `oidc_logout_revocations` table and answers `200` only after the row is committed. The unique `(issuer, jti)` key makes every `jti` single-use. `EnsureOidcSessionIsActiveMiddleware`, run in the `web` group after the session starts and before `auth`, ends the matching local sessions on their next request:

- with `sid`, only the sessions that came from that IdP session;
- with `sub` alone, every session of the user authenticated at or before the logout.

Rejected requests count toward `oidc.backchannel_logout.rate_limit` (600 per minute per sender IP by default, `null` disables it). Further rejections from that IP return `429` with `Retry-After` and omit the diagnostic log message. Every valid logout still runs during a burst. Behind a reverse proxy, configure Laravel's `TrustProxies` with the actual proxy addresses so rejected requests are counted against the sender's IP.

**The table is the source of truth; the cache is only an accelerator.** A cache hit ends the session at once, but a cache miss is never read as "not revoked": only the table answers that, so `cache:clear`, eviction or a cache per server never loses a logout. If the table cannot be read, the session is treated as revoked (fail closed) and the error is logged.

A logout row, including one with only a session ID, stays active for at least the Laravel `session.lifetime` in effect when it is written. The row can live longer to satisfy `oidc.backchannel_logout.revocation_ttl` or to cover the logout token's expiry plus the greater of 120 seconds and the JWT clock leeway. The application chooses its database retention ceiling through `oidc.backchannel_logout.max_retention_seconds`. It defaults to 30 days. Increase it only to cover longer sessions or replay windows required by the application. With `oidc.enabled=true`, the package refuses to boot if `session.lifetime` exceeds the ceiling. The runtime session check also ends OIDC sessions if their configured lifetime exceeds the ceiling, including when a custom provider repository enables SSO. The logout endpoint refuses tokens whose replay window exceeds the ceiling. Each cache entry expires within 24 hours, and the database can still revoke a session after its cache entry expires. Schedule the prune command hourly to remove rows after their retention window.

```php
Schedule::command('oidc:prune-logout-revocations')->hourly();
```

The model is also `MassPrunable`, so `model:prune` has the same effect. A missed run only leaves extra rows.

Every stored logout, back-channel or front-channel, dispatches `OidcLogoutReceivedEvent` after its row is committed: `channel` (`backchannel` or `frontchannel`), `issuer`, `subject` (null for front-channel) and `sessionIdHash` (the SHA-256 of `sid`, or null). Listen to it to write the logout into the app's activity log; a refused or replayed logout dispatches nothing. A listener that throws is logged and does not fail the logout, which is already stored; a queued listener is still the better choice for slow work.

### Front-channel logout

Off by default. Back-channel logout already ends server sessions; front-channel logout (OIDC Front-Channel Logout 1.0) is for an IdP that can only notify the browser. To turn it on:

1. Set `OIDC_FRONTCHANNEL_LOGOUT=true` (`oidc.frontchannel_logout.enabled`).
2. Register `{APP_URL}/auth/oidc/frontchannel-logout` (printed by `oidc:configure`) at the IdP as the front-channel logout URI, with "front-channel logout session required" (`frontchannel_logout_session_required`), so the IdP appends `iss` and `sid`.
3. Let the response be framed by the IdP. The endpoint sends `Content-Security-Policy: frame-ancestors <issuer origin>` and `Cache-Control: no-store`; an app middleware that forces `X-Frame-Options: DENY` or `frame-ancestors 'none'` on every response must skip this route.

The endpoint needs both `iss` and `sid`, requires `iss` to equal the configured issuer exactly, and records the logout in the same table with `channel = frontchannel`, so the middleware ends the session as for back-channel logout. It uses no session cookie (a cross-site iframe does not send a `SameSite=lax` cookie) and is rate limited.

Repeated notices for the same issuer and SID return success while the revocation is active. A notice after expiry creates a fresh revocation even if pruning has yet to run. The unique `(issuer, replay_key)` index makes active notices idempotent across servers. The front-channel SID digest has its own namespace, so a signed back-channel token can still record a separate revocation.

### Erasing a user's OIDC data

Call the eraser from the product's erasure orchestrator after it has blocked sign-in and invalidated the user's sessions. Pass the local user key as a decimal string and the user public ID as a UUID. The optional `publicIds` list can also match a package identity by its public UUID.

```php
use Qiick\Oidc\Erasure\OidcEraser;

$report = app(OidcEraser::class)->erase(
    userId: (string) $user->getKey(),
    userPublicId: $user->public_id,
    mode: OidcEraser::DELETE,
    dryRun: true,
);
```

Set `dryRun: false` to apply the preview. `DELETE` deletes the identity rows. `ANONYMISE` leaves unlinkable rows and clears their profile and sign-in history. The eraser keeps the app's user row and explicitly processes the identity links before any foreign-key cascade. Passing an organisation ID throws `OrganisationScopeUnsupportedException`, since an OIDC identity is shared across organisations.

Both modes remove the personal fields and cache entries of revocations identified by issuer and subject, including session-only rows when that issuer has a single corroborating subject for the session ID. Signed logout rows keep a token fingerprint until expiry to preserve replay protection. Rows with an uncorroborated or ambiguous session ID follow the same retention window as other logout records. The report counts unresolved session-only rows for the affected issuers and reports their unresolved SID cache entries as `cache_ttl`. Each cache entry expires within 24 hours. Raw app session data and logout events stored by app listeners remain under the product's erasure and retention policy.

The report uses the fleet's `security_log` reason for retained logout evidence. The configured logout retention ceiling applies to those entries.

Each real run dispatches `SubjectErasedEvent` after commit with an aggregate `ErasureReport`. Repeating a completed run yields `changed() === 0`.

### Settings from the database

Externa and Excubia App keep their OIDC settings in a settings table. Bind your own repository after the package provider:

```php
$this->app->bind(ProviderConfigurationRepositoryContract::class, DatabaseOidcSettingsRepository::class);
```

### Advanced configuration

| Config key | Default | Meaning |
| --- | --- | --- |
| `oidc.allowed_domains` | `[]` | JIT only for these email domains; empty allows all. |
| `oidc.require_verified_email` | `true` | Auto-link and JIT need `email_verified: true` (**on by default**, Decision Luca, 2026-11-13). Turn off only for an IdP whose emails the organisation controls (Entra ID sends no `email_verified`). |
| `oidc.remember` | `false` | Use the remember-me cookie for SSO logins (**off by default**; a remember cookie would outlive IdP logout). |
| `oidc.home` / `oidc.login_url` | `/` / `/login` | Where a successful and a failed SSO login land. |
| `oidc.users.model` | `null` | The user model; `null` uses `auth.providers.users.model`. |
| `oidc.users.table` / `email_column` / `active_column` | `users` / `email` / `null` | The users table, its email column and an optional boolean "active" column. |
| `oidc.break_glass.roles` / `require_two_factor` / `query_parameter` | `['super-admin']` / `true` / `local` | SSO-only mode, see above. |
| `oidc.roles.*` | disabled | Role mapping, see above. |
| `oidc.mfa.required` / `amr_values` / `acr_values` / `request_acr_values` | `false` / `['mfa']` / `['urn:qiick:loa:mfa']` / `null` | Second factor, see above. |
| `oidc.mfa.max_age` / `require_requested_acr` | `null` / `false` | Recent login and strict `acr`, see "Second factor (MFA)". |
| `oidc.post_logout_redirect_uri` | `null` | `null` means the package return route `{APP_URL}/auth/oidc/logged-out`, which checks the logout `state`. Sent on RP-initiated logout. |
| `oidc.logout.redirect_to` | `/` | Where the post-logout return route sends the browser. |
| `oidc.userinfo` | `true` | Merge the userinfo claims into the identity. |
| `oidc.routes.enabled` / `prefix` / `middleware` | `true` / `auth/oidc` / `['web', 'guest']` | The package routes; `middleware` applies to redirect and callback. |
| `oidc.routes.except` | `[]` | Names of package routes the app registers itself (for example `['oidc.callback']`); every other package route is still registered. |
| `oidc.backchannel_logout.rate_limit` | `600` | Rejected requests per minute per sender IP. Null disables the limit. |
| `oidc.backchannel_logout.revocation_ttl` | `null` | Optional minimum retention in seconds. Null uses the app's session lifetime. |
| `oidc.backchannel_logout.max_retention_seconds` | `2592000` | App-selected database retention ceiling in seconds. It must cover `session.lifetime` converted from minutes and the longest accepted logout replay window. |
| `oidc.frontchannel_logout.enabled` (`OIDC_FRONTCHANNEL_LOGOUT`) | `false` | Turns on the front-channel logout endpoint, see above. |
| `oidc.redirect_uri` | `null` | `null` means `{APP_URL}/auth/oidc/callback`, the URI Externa and Excubia App already register. |
| `oidc.scopes` | `openid profile email` | `openid` is always sent. Add `qiick.orgs` for Signaculum's organisation claims. |
| `oidc.token_endpoint_auth_method` | `client_secret_basic` | Or `client_secret_post`. A client without secret is a public client. |
| `oidc.id_token.algorithms` | `['RS256']` | Accepted signing algorithms; only `RS256`, `RS384`, `RS512`, `PS256`, `ES256` and `ES384` can be enabled. |
| `oidc.id_token.leeway` | `60` | Clock skew in seconds. |
| `oidc.id_token.trusted_audiences` | `[]` | Extra `aud` values to accept; `azp` must then be the client id. |
| `oidc.cache.store` | `null` | Cache store for discovery, JWKS and the single-use login `state`; `null` is the app's default store. With several app servers it must be a store they share (database, redis). The array driver is refused unless `APP_ENV` is `testing` (`oidc:configure` warns even then, and warns about the per-server file driver). |
| `oidc.cache.discovery_ttl` / `jwks_ttl` | `21600` / `3600` | Cache lifetimes in seconds. |
| `oidc.cache.jwks_refetch_cooldown` | `30` | Minimum seconds between JWKS refetches on an unknown `kid`. |
| `oidc.http.discovery_base` (`OIDC_DISCOVERY_BASE`) | `null` | Docker: fetch discovery from this base instead of the issuer. |
| `oidc.http.server_origin` (`OIDC_SERVER_ORIGIN`) | `null` | Docker: scheme and host for the token, userinfo and JWKS calls. |
| `oidc.http.allow_private_hosts` (`OIDC_ALLOW_PRIVATE_HOSTS`) | `false` | Allow an IdP on a private network and plain http. Cloud metadata stays blocked. Mapped onto `qiick/laravel-outbound` `UrlGuardOptions`. |
| `oidc.http.timeout` (`OIDC_HTTP_TIMEOUT`) | `10` | Per-hop IdP timeout in seconds; `0` means no practical limit. |
| `oidc.http.connect_timeout` (`OIDC_HTTP_CONNECT_TIMEOUT`) | `10` | TCP connect timeout in seconds; `0` means no practical limit. |
| `oidc.http.max_response_bytes` (`OIDC_MAX_RESPONSE_BYTES`) | `1048576` | Cap on IdP response bodies (discovery, JWKS, token, userinfo). |

### Fields for an app's settings UI

The package ships no UI. An app that edits SSO in an admin page (Externa and Excubia App keep it in a settings table, see "Settings from the database") shows the basic fields always and the advanced ones in a collapsible section, closed by default. Every advanced field is optional, defaults to the package default and validates on save, so settings stored before a field existed still boot. The first four are read from `ProviderConfigurationData`; the others are config keys the app sets at runtime from its settings.

**Basic:** enabled (`oidc.enabled`), issuer, client id, client secret (write-only: show only whether one is stored), button label, JIT (`oidc.jit`), auto-link (`oidc.auto_link`, with a warning that it lets the IdP take over a local account with the same verified email), SSO-only (`oidc.only`), and the URIs to register at the IdP with copy buttons: redirect, post-logout redirect and back-channel logout (`oidc:configure --json` prints them).

**Advanced:**

| Field | Where | Validation |
| --- | --- | --- |
| Scopes | `ProviderConfigurationData::$scopes` (`oidc.scopes`) | non-empty strings; `openid` is always sent |
| Token endpoint auth method | `ProviderConfigurationData::$tokenEndpointAuthMethod` | `client_secret_basic` or `client_secret_post` |
| Post-logout redirect URI | `ProviderConfigurationData::$postLogoutRedirectUri` | absolute URL or empty (the package return route) |
| Recent login (`max_age`) | `ProviderConfigurationData::$maxAge` (`oidc.mfa.max_age`) | whole seconds, 0 or more, or empty |
| Require verified email | `oidc.require_verified_email` | boolean |
| Allowed email domains | `oidc.allowed_domains` | list of domains; empty allows all |
| MFA required | `oidc.mfa.required` | boolean |
| Accepted `amr` / `acr` values | `oidc.mfa.amr_values` / `acr_values` | lists of strings |
| Requested `acr_values` | `oidc.mfa.request_acr_values` | space-separated string or empty |
| Refuse a login without a requested `acr` | `oidc.mfa.require_requested_acr` | boolean |
| Role mapping | `oidc.roles.enabled` / `claim` / `organization` / `map` / `forbidden` | see "Role mapping" |
| ID token algorithms | `oidc.id_token.algorithms` | subset of `RS256`, `RS384`, `RS512`, `PS256`, `ES256`, `ES384` |
| Trusted audiences | `oidc.id_token.trusted_audiences` | list of strings |
| Clock leeway | `oidc.id_token.leeway` | seconds, 0 or more |
| Fetch userinfo | `oidc.userinfo` | boolean |
| Remember-me for SSO | `oidc.remember` | boolean; warn that the cookie outlives a logout |
| Front-channel logout | `oidc.frontchannel_logout.enabled` | boolean; show the front-channel URI to copy when on |

Next to a field, the UI can say "not supported by this IdP" from the capabilities `oidc:configure --json` reports under `identity_provider_capabilities` (for example `acr_values_supported` for the `acr` fields, `frontchannel_logout_session_supported` for front-channel logout). These hints never block saving.

### Testing your app

The package ships an in-memory IdP, so app tests need no network:

```php
use Qiick\Oidc\Testing\FakeIdentityProvider;

$identityProvider = FakeIdentityProvider::fake(); // Http::fake() + config('oidc.*')
$authorizationUrl = $this->get('/auth/oidc/redirect')->headers->get('Location');
$callbackUrl = $identityProvider->authorize($authorizationUrl, ['sub' => 'user-42', 'email' => 'ada@example.com']);
$this->get($callbackUrl);
```

It checks the PKCE verifier, the code, the redirect URI and the client secret like a strict IdP, and signs `id_token`s with a key generated per test. `authorize()` also takes userinfo claims, and `logoutTokenClaims()` + `sign()` build back-channel logout tokens. `withDiscovery()`, `rotateSigningKey()`, `sign()` and `modifyTokenResponseUsing()` cover the failure cases. `rotateSigningKey(keyType: 'EC', curve: 'P-384')` and `sign(..., algorithm: 'ES384')` cover EC keys; RSA keys sign every `RS*` algorithm and `PS256`.

## Threat model

What the package defends against, and what it leaves to the app and the IdP. Decided with the standards review (S10, 2026-11-22); this section is kept in step with the code.

**Trusted:** the IdP's signing keys published at its `jwks_uri`, the issuer configured by the app, the app key (`APP_KEY`), the app's database and its config. **Not trusted:** the browser and every query parameter it carries, the userinfo response (unsigned), the IdP's network responses until validated, and any URL in the discovery document.

| Threat | Defence |
| --- | --- |
| Forged or replayed login response | `state` checked and single-use per pending login (at most five per session, ten minutes each); PKCE `S256` on every login (RFC 7636); `nonce` bound to the `id_token` (OIDC Core 3.1.3.7); RFC 9207 `iss` checked whenever present, and required when the IdP advertises it. |
| Forged or substituted `id_token` | Signature through the IdP's JWKS with an allowlist of algorithms (never `none` or HMAC), RSA keys of 2048 bits or more, EC keys on their own curve; `iss`, `aud`, `azp`, `exp`, `iat`, `at_hash`, `auth_time` against `max_age`; a `crit` header is refused. |
| Substituted userinfo | Its `sub` must equal the `id_token` `sub` (OIDC Core 5.3.4). A claim in the `id_token` always wins over userinfo, and `amr`, `acr`, `auth_time`, `sid`, `azp` and `nbf` are never taken from userinfo. |
| Account takeover through email | Auto-link is off by default and needs `email_verified: true`; one user links to at most one identity per issuer (unique key), and concurrent first logins cannot link twice. |
| MFA bypass | Only a signed `amr` / `acr` counts as MFA; a login that asked for an `acr` and got another one runs the app's second factor (or is refused). |
| A logout that is lost | Back-channel and front-channel logouts are stored in `oidc_logout_revocations` before the endpoint answers. **The table is the source of truth; the cache is only an accelerator**, so `cache:clear`, eviction or one cache per server never loses a logout. A failed table read ends the session (fail closed). |
| Replayed `logout_token` | Unique `(issuer, jti)`: a second use is refused. |
| Session theft from storage | The `id_token` kept for logout is encrypted with the app key; access and refresh tokens are not stored. An unknown session payload version ends the session. |
| SSRF through discovery | Every server-side call (discovery, JWKS, token, userinfo) goes through `qiick/laravel-outbound`: https only, private, loopback and metadata addresses refused (unless `oidc.http.allow_private_hosts`, which still blocks metadata), the resolved address pinned, response size and time capped. |
| Open redirect after logout | The post-logout return route redirects only to `oidc.logout.redirect_to` from config, and checks the logout `state` cookie. |
| Lock-out by a broken IdP | SSO-only mode always keeps break-glass accounts (role plus confirmed second factor), and turning SSO off restores local login. |
| Secrets in logs | Tokens, codes, secrets and full claim sets are never logged; the client secret is never printed by `oidc:configure`. |

**Out of scope, left to the app or the IdP:**

- A compromised IdP or a stolen IdP signing key: the package trusts what the IdP signs.
- The app's own login, second factor and session hardening (cookie flags, session lifetime, `APP_KEY` rotation with `APP_PREVIOUS_KEYS`).
- Rate limiting of the login redirect and callback routes: add `throttle` to `oidc.routes.middleware` or the app's route group if needed.
- Schedule `oidc:prune-logout-revocations` hourly so expired rows can be removed on the next successful run.
- Clock drift beyond `oidc.id_token.leeway` and an `app.timezone` other than `UTC`.

## Migrating Externa and Excubia App

[`docs/MIGRATION.md`](./docs/MIGRATION.md) replaces the copied Socialite client step by step. It covers the behaviour changes to announce, `oidc:import-legacy-subjects` for `users.oidc_sub`, settings from the database, provisioning, 2FA, SSO-only mode, the login page, logout, the files to delete and the tests.

## Development

```bash
composer install
composer test      # Pest + Testbench
composer lint      # Pint
composer analyse   # PHPStan, level max
```

The default suite never uses the network. The end-to-end tests against real IdPs run in CI (`keycloak`, `signaculum`, `zitadel`) and locally with Docker:

```bash
docker run -d --name laravel-oidc-keycloak -p 8180:8080 \
  -v "$PWD/tests/Fixtures/Keycloak:/opt/keycloak/data/import:ro" \
  quay.io/keycloak/keycloak:26.2 start-dev --import-realm
KEYCLOAK_URL=http://localhost:8180 vendor/bin/pest --group=keycloak

bash tests/Fixtures/signaculum/prepare.sh   # Signaculum from a sibling checkout
source "${TMPDIR:-/tmp}/laravel-oidc-signaculum-run/env.sh"
vendor/bin/pest --group=signaculum

bash tests/Fixtures/zitadel/prepare.sh   # Zitadel v4.16.0 + Postgres 17.10
source "${TMPDIR:-/tmp}/laravel-oidc-zitadel-run/env.sh"
vendor/bin/pest --group=zitadel
```

## Contributing and security

See [CONTRIBUTING.md](./CONTRIBUTING.md). Report vulnerabilities privately, as described in [SECURITY.md](./SECURITY.md). Every security check, with its spec and the tests that refuse a bad value, is listed in [`docs/SECURITY-CHECKLIST.md`](./docs/SECURITY-CHECKLIST.md).

The package passes the OpenID Foundation conformance suite's relying-party plans (Basic, Config, RP-initiated, back-channel and front-channel logout). Results, the local harness and the certification path are in [`docs/conformance/openid.md`](./docs/conformance/openid.md).

## License

MIT. See [LICENSE](./LICENSE).
