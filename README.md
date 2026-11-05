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

> **Status:** in development, not released. Nothing here is a stable contract yet.

`qiick/laravel-oidc` is an OpenID Connect client for Laravel apps: PKCE, `id_token` validation, logout, role mapping. It works with any standard identity provider: Keycloak, Zitadel, Authentik, Microsoft Entra ID, Google Workspace or Signaculum. It is the shared SSO login of the [qiick](https://qiick.io) apps and replaces the OIDC client that Externa and Excubia App each carry today.

SSO is optional. An app that installs the package keeps its local login (email and password, 2FA, passkeys), and SSO stays off until it is configured.

## Requirements

- PHP 8.3 or newer
- Laravel 12 or 13

## Installation

```bash
composer require qiick/laravel-oidc
php artisan vendor:publish --tag=oidc-config
php artisan migrate
php artisan oidc:configure --issuer=https://idp.example.com/realms/acme --client-id=my-app --client-secret=...
```

`oidc:configure` checks the setup against the IdP without a browser:
- settings, discovery (exact issuer, code flow, PKCE `S256`), end-session support;
- signing algorithms and JWKS keys, client type, redirect URI;
- in SSO-only mode, that a break-glass account exists.

It prints the URIs to register at the IdP: the redirect URI, the post-logout redirect URI and the back-channel logout URI. `--json` prints a machine-readable report for agents. `--write-env` writes `OIDC_ENABLED`, `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` to `.env`, only when every check passed. The exit code is `0` without failures. The client secret is never printed.

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
| `OIDC_AUTO_LINK` | `oidc.auto_link` | `false` | Link to an existing local user with the same verified email. Turn on only for a trusted IdP. |
| `OIDC_ONLY` | `oidc.only` | `false` | SSO-only mode: hide the password form; a break-glass local admin still works. |

## Protocol profile

What the package implements, from the accepted Signaculum SSO design (2026-11-05):

- **Flow:** authorization code with PKCE `S256` only, also for confidential clients. `state` and `nonce` on every login. No implicit flow, no password grant.
- **`id_token`:** signed `RS256` (`ES256` optional), validated on every login: signature through the JWKS (cached, refetched on an unknown `kid`), `iss`, `aud`, `exp`, `iat`, `nonce`, and `azp` when present.
- **Session:** after the callback the app keeps its own Laravel session, regenerated. Access and refresh tokens are not stored.
- **Logout:** RP-initiated logout (`end_session_endpoint`, `id_token_hint`, `post_logout_redirect_uri`) and back-channel logout (signed `logout_token`, matched by `sid` / `sub`). No front-channel logout.
- **Claims:** `sub`, `email`, `email_verified`, `name`, `preferred_username`, `picture`, `locale`, `amr` / `acr`. Provider-specific claims, such as an `orgs` claim for roles, are read through config, never hard-coded.
- **Identity key:** the pair (`issuer`, `sub`), stored in a `user_identities` table.

## Usage

```bash
php artisan migrate   # creates user_identities
```

The package registers these routes under `oidc.routes.prefix` (`auth/oidc`):

| Route | Name | Middleware | Purpose |
| --- | --- | --- | --- |
| `GET /auth/oidc/redirect` | `oidc.redirect` | `web`, `guest` | The SSO button: sends the browser to the IdP. |
| `GET /auth/oidc/callback` | `oidc.callback` | `web`, `guest` | The redirect URI to register at the IdP. |
| `POST /auth/oidc/backchannel-logout` | `oidc.backchannel-logout` | none | The back-channel logout URI to register at the IdP. |

Point your SSO button at `route('oidc.redirect')`. The callback validates everything (see the protocol profile), finds or creates the local user, logs them in on the default guard, regenerates the session and redirects to `redirect()->intended(config('oidc.home'))`. On failure it redirects to `oidc.login_url` with a message under the `email` key: a refusal says why (inactive user, no linked account, ...), and a protocol or IdP failure shows a generic message and logs the technical one.

### Linking SSO identities to local users

The identity key is (`issuer`, `sub`), stored in `user_identities`. On each login:

1. If (issuer, sub) is already linked, that user signs in. The email does not matter.
2. Otherwise, with `OIDC_AUTO_LINK`, the local user with the same **verified** email is linked, unless that user is already linked to another identity of this issuer. Turn it on only for an IdP where users cannot choose an arbitrary email.
3. Otherwise, with `OIDC_JIT`, a new user is created if the email domain is in `oidc.allowed_domains` (empty allows all). An existing account with that email is never duplicated.
4. Otherwise the login is refused.

Users with `false` in `oidc.users.active_column` (for example `is_active`) are always refused. The default JIT provisioning fills `name`, `email`, an unusable random password and `email_verified_at`. Apps with other columns or a default role bind their own provisioning:

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
- For an IdP with a flat role or group list, set `claim` to its path (Keycloak `realm_access.roles`, Entra ID `roles`) and leave `organization` null.

The default `RoleSynchronizationContract` calls spatie/laravel-permission's `hasRole` / `assignRole` / `removeRole`. A mapped role missing in the app is skipped with a warning.

### Second factor (MFA)

When the app requires 2FA for a user, an SSO login counts only if the signed `id_token` proves MFA: an `amr` value in `oidc.mfa.amr_values` (default `['mfa']`, RFC 8176), or an `acr` in `oidc.mfa.acr_values`. Otherwise the callback hands over to the app's own challenge instead of signing the user in. The challenge must end with `Auth::login()`, and the package then completes the SSO session (identity for logout). `amr` and `acr` are never taken from the unsigned userinfo response.

The default `SecondFactorChallengeContract` reads `oidc.mfa.required` and starts Laravel Fortify's two-factor challenge (`login.id` / `login.remember` and the `two-factor.login` route) for a user with a confirmed TOTP secret. A user without a second factor is signed in, and the app's own enrollment rules apply, as after a password login. Apps bind their own implementation to read their "2FA required" setting:

```php
$this->app->bind(SecondFactorChallengeContract::class, SsoSecondFactorChallengeService::class);
```

`oidc.mfa.request_acr_values` asks the IdP for a stronger login (`acr_values` on the authorization request).

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

Register `oidc.post_logout_redirect_uri` (default `{APP_URL}/`) as a post-logout redirect URI at the IdP.

### Back-channel logout

The package registers `POST /auth/oidc/backchannel-logout` (route `oidc.backchannel-logout`, no session, no CSRF). Register its absolute URL at the IdP as the back-channel logout URI. The endpoint validates the signed `logout_token`: signature, `iss`, `aud`, `exp`, `iat`, the logout `events` member, no `nonce`, `sub` or `sid`, and a single-use `jti`. It then records the logout in the cache. `EnsureOidcSessionIsActiveMiddleware`, appended to the `web` group, ends the matching local sessions on their next request:

- with `sid`, only the sessions that came from that IdP session;
- with `sub` alone, every session of the user created before the logout.

The cache store must be shared by all app servers. `oidc.backchannel_logout.revocation_ttl` (default `session.lifetime`) must cover your longest session.

### Settings from the database

Externa and Excubia App keep their OIDC settings in a settings table. Bind your own repository after the package provider:

```php
$this->app->bind(ProviderConfigurationRepositoryContract::class, DatabaseOidcSettingsRepository::class);
```

### Advanced configuration

| Config key | Default | Meaning |
| --- | --- | --- |
| `oidc.allowed_domains` | `[]` | JIT only for these email domains; empty allows all. |
| `oidc.require_verified_email` | `true` | Auto-link and JIT need `email_verified: true`. Turn off only for an IdP whose emails the organisation controls (Entra ID sends no `email_verified`). |
| `oidc.remember` | `false` | Use the remember-me cookie for SSO logins. |
| `oidc.home` / `oidc.login_url` | `/` / `/login` | Where a successful and a failed SSO login land. |
| `oidc.users.model` | `null` | The user model; `null` uses `auth.providers.users.model`. |
| `oidc.users.table` / `email_column` / `active_column` | `users` / `email` / `null` | The users table, its email column and an optional boolean "active" column. |
| `oidc.break_glass.roles` / `require_two_factor` / `query_parameter` | `['super-admin']` / `true` / `local` | SSO-only mode, see above. |
| `oidc.roles.*` | disabled | Role mapping, see above. |
| `oidc.mfa.required` / `amr_values` / `acr_values` / `request_acr_values` | `false` / `['mfa']` / `[]` / `null` | Second factor, see above. |
| `oidc.post_logout_redirect_uri` | `null` | `null` means `{APP_URL}/`. Sent on RP-initiated logout. |
| `oidc.userinfo` | `true` | Merge the userinfo claims into the identity. |
| `oidc.routes.enabled` / `prefix` / `middleware` | `true` / `auth/oidc` / `['web', 'guest']` | The package routes; `middleware` applies to redirect and callback. |
| `oidc.backchannel_logout.revocation_ttl` | `null` | Seconds a back-channel logout is remembered; `null` uses `session.lifetime`. |
| `oidc.redirect_uri` | `null` | `null` means `{APP_URL}/auth/oidc/callback`, the URI Externa and Excubia App already register. |
| `oidc.scopes` | `openid profile email` | `openid` is always sent. Add `qiick.orgs` for Signaculum's organisation claims. |
| `oidc.token_endpoint_auth_method` | `client_secret_basic` | Or `client_secret_post`. A client without secret is a public client. |
| `oidc.id_token.algorithms` | `['RS256']` | Accepted signing algorithms; only `RS*`, `PS256` and `ES*` can be enabled. |
| `oidc.id_token.leeway` | `60` | Clock skew in seconds. |
| `oidc.id_token.trusted_audiences` | `[]` | Extra `aud` values to accept; `azp` must then be the client id. |
| `oidc.cache.store` | `null` | Cache store for discovery and JWKS. |
| `oidc.cache.discovery_ttl` / `jwks_ttl` | `21600` / `3600` | Cache lifetimes in seconds. |
| `oidc.cache.jwks_refetch_cooldown` | `30` | Minimum seconds between JWKS refetches on an unknown `kid`. |
| `oidc.http.timeout` | `10` | Seconds per IdP request. |
| `oidc.http.discovery_base` (`OIDC_DISCOVERY_BASE`) | `null` | Docker: fetch discovery from this base instead of the issuer. |
| `oidc.http.server_origin` (`OIDC_SERVER_ORIGIN`) | `null` | Docker: scheme and host for the token, userinfo and JWKS calls. |
| `oidc.http.allow_private_hosts` (`OIDC_ALLOW_PRIVATE_HOSTS`) | `false` | Allow an IdP on a private network and plain http. Cloud metadata stays blocked. |

### Testing your app

The package ships an in-memory IdP, so app tests need no network:

```php
use Qiick\Oidc\Testing\FakeIdentityProvider;

$identityProvider = FakeIdentityProvider::fake(); // Http::fake() + config('oidc.*')
$authorizationUrl = $this->get('/auth/oidc/redirect')->headers->get('Location');
$callbackUrl = $identityProvider->authorize($authorizationUrl, ['sub' => 'user-42', 'email' => 'ada@example.com']);
$this->get($callbackUrl);
```

It checks the PKCE verifier, the code, the redirect URI and the client secret like a strict IdP, and signs `id_token`s with a key generated per test. `authorize()` also takes userinfo claims, and `logoutTokenClaims()` + `sign()` build back-channel logout tokens. `withDiscovery()`, `rotateSigningKey()`, `sign()` and `modifyTokenResponseUsing()` cover the failure cases.

## Migrating Externa and Excubia App

[`docs/MIGRATION.md`](./docs/MIGRATION.md) replaces the copied Socialite client step by step. It covers the behaviour changes to announce, `oidc:import-legacy-subjects` for `users.oidc_sub`, settings from the database, provisioning, 2FA, SSO-only mode, the login page, logout, the files to delete and the tests.

## Development

```bash
composer install
composer test      # Pest + Testbench
composer lint      # Pint
composer analyse   # PHPStan, level max
```

The default suite never uses the network. The end-to-end tests against a real Keycloak 26 run in CI (`keycloak` job) and locally with Docker:

```bash
docker run -d --name laravel-oidc-keycloak -p 8180:8080 \
  -v "$PWD/tests/Fixtures/Keycloak:/opt/keycloak/data/import:ro" \
  quay.io/keycloak/keycloak:26.2 start-dev --import-realm
KEYCLOAK_URL=http://localhost:8180 vendor/bin/pest --group=keycloak
```

## Contributing and security

See [CONTRIBUTING.md](./CONTRIBUTING.md). Report vulnerabilities privately, as described in [SECURITY.md](./SECURITY.md).

## License

MIT. See [LICENSE](./LICENSE).
