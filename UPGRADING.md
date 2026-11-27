# Upgrading

What an app has to do for each pre-release, newest first. The [CHANGELOG](./CHANGELOG.md) lists every change; this page says what to act on. The public API that `1.0.0` freezes is in [`docs/PUBLIC-API.md`](./docs/PUBLIC-API.md).

## From any beta to 1.0.0-beta.9, in one pass

1. Update OIDC and Outbound together. If the app still uses the Outbound beta, require it explicitly in the root project.

   ```bash
   composer require 'qiick/laravel-oidc:1.0.0-beta.9' 'qiick/laravel-outbound:^0.2.0-beta.4' --with-all-dependencies
   ```

   A compatible Outbound `^1.0` release also satisfies OIDC. Follow Outbound's upgrade notes for any webhook tables you use.
2. If upgrading from beta.7 or earlier, bring the two package tables up to the beta.8 schema. If you published the migrations, back up the old package copies, remove them and run `vendor:publish --tag=oidc-migrations`. Locally, use `php artisan migrate:fresh --seed` only on a disposable database. On a shared installation, back up `user_identities`, recreate `user_identities` and `oidc_logout_revocations` from the package migrations, then restore identities and expire OIDC sessions. A user can keep one identity per issuer. Review the linked identities for duplicates before restoring them. Databases migrated with beta.8 already have the required schema.
3. Keep your published `config/oidc.php`. Missing keys get the shipped defaults. Boot reports the key and expected type for an invalid value.
4. Apply the MFA settings below before enabling SSO on the upgraded app.
5. Register `{APP_URL}/auth/oidc/logged-out` at the IdP as a post-logout redirect URI and set `oidc.logout.redirect_to`.
6. Point `oidc.cache.store` at a store every app server shares, such as a database or Redis, to consume each login state once.
7. Keep `oidc:prune-logout-revocations` scheduled hourly with Laravel's `onOneServer()` on a shared scheduler cache.
8. Run `php artisan oidc:check` and exercise a real login and logout before switching users over.

Read the notes for each beta you skipped for changes that affect your app.

## 1.0.0-beta.9 (from 1.0.0-beta.8)

**Before deploying with `oidc.mfa.required = true`, verify the second-factor setup.** Users who rely on IdP MFA and have no local second factor need explicit provider trust. With `oidc.only = true`, verify a working local break-glass login before the upgrade.

For Signaculum installations that rely on MFA at the IdP, set these values in the `mfa` section of the published `config/oidc.php`.

```php
'mfa' => [
    'required' => true,
    'trust_provider' => true,
    'amr_values' => ['mfa'],
    'acr_values' => ['urn:qiick:loa:mfa'],
    // Keep your other published MFA settings.
],
```

For another IdP, verify its signed claims before setting the accepted values. For local-only MFA, clear both provider allowlists and enroll users or bind a working second-factor adapter. `oidc:check` shares setup diagnostics with `oidc:configure` and exits non-zero for ignored lists or required MFA without a usable configured path. Check custom adapters with a real login. A required challenge that returns `null` refuses the login and rolls back JIT provisioning and role changes on the provisioning connection.

Back-channel logout counts rejected requests against `oidc.backchannel_logout.rate_limit` (600 per sender IP per minute by default, `null` to disable). Configure Laravel's `TrustProxies` if OIDC sits behind a reverse proxy. Beta.9 uses the replay index and schema shipped with beta.8.

## 1.0.0-beta.8 (from 1.0.0-beta.7)

- Recreate the beta package tables using the procedure above. The identity owner key becomes nullable for anonymised rows, and logout revocations add a replay fingerprint. Preserve linked identities from a backup and expire OIDC sessions when replacing the logout revocation table.
- The app continues to control OIDC session duration. The new `oidc.backchannel_logout.max_retention_seconds` defaults to 30 days. Before deploying, choose a ceiling that covers `session.lifetime` (minutes) and the IdP's logout token lifetime plus its replay allowance. Schedule `oidc:prune-logout-revocations` hourly.
- Call `OidcEraser` from the product erasure orchestrator before deleting the user. The identity foreign key still cascades as a safety net.
- Keep `OIDC_ALLOW_PRIVATE_HOSTS=true` for an IdP on a private network. It now takes effect with outbound v0.2.0-beta.2.

## 1.0.0-beta.7 (from 1.0.0-beta.6)

- **Database:** recreate the package tables (step 3 above). `user_identities` has a unique `(user_id, issuer)` key instead of a plain index.
- **Post-logout return route:** see below. Until the new URI is registered, logout does not end the IdP session.
- **Encrypted `id_token` in the session:** the session payload moves to `format_version` 2 and the stored `id_token` is encrypted with `APP_KEY`. Version 1 sessions written by beta.6 are still read and re-encrypted, so the upgrade signs nobody out. Rotating `APP_KEY` without listing the old key in `APP_PREVIOUS_KEYS` now signs SSO users out.
- **Single-use login `state`:** the callback consumes each `state` on `oidc.cache.store` (the app's default store when null). With several app servers that store must be shared; the array driver refuses every SSO callback unless `APP_ENV` is `testing`. `oidc:configure` checks it.
- **Requested `acr`:** a login that asked for an `acr` (`oidc.mfa.request_acr_values`, `acr_values` or the `claims` parameter) and got none of the requested values no longer counts as MFA, even with `amr=mfa`: the app's second factor runs. Set `oidc.mfa.require_requested_acr = true` to refuse such a login instead.
- **Recent login:** new `oidc.mfa.max_age` (or `ProviderConfigurationData::$maxAge` from an app repository). `AuthorizationCodeFlowService::redirect()` throws `InvalidArgumentException` for a `max_age` that is not a whole number of seconds, 0 or more.
- **Missing email:** a login whose `id_token` and userinfo carry no email is refused with the new reason `email_not_released`. An app that maps `LoginRefusalReasonEnum` cases to its own messages adds that case.
- **`oidc:import-legacy-subjects`:** the issuer comes from the bound `ProviderConfigurationRepositoryContract`, never `oidc.issuer`. While SSO is not configured, pass `--issuer`. `--dry-run` now works before the package migration.
- **Logout route throttle:** `GET /auth/oidc/logged-out` allows 60 requests a minute.
- **Logout event:** `OidcLogoutReceivedEvent` is dispatched for every stored logout; listen to it for the app's activity log.
- **Code that builds internal classes by hand** (prefer the container; they are `@internal`, see `docs/PUBLIC-API.md`): `AuthorizationCodeFlowService` takes `leewaySeconds`, `isRequestedAcrRequired`, `cache` and `isArrayCacheAllowed`; `SessionRevocationService` takes the event dispatcher and `leewaySeconds`; `FortifySecondFactorChallengeService` takes optional Fortify class names (test hooks). Removed: `IdentityProviderHttpService::UnlimitedTimeoutSeconds`, `IdentitySessionService::PENDING_SECONDS`, `RoleMappingService::ALWAYS_FORBIDDEN_ROLES`; `JwtValidatorService::SUPPORTED_ALGORITHMS` is now `JwtValidatorService::supportedAlgorithms()`.

### Post-logout return route

RP-initiated logout now sends a `state` and, by default, asks the IdP to return to the package route `{APP_URL}/auth/oidc/logged-out`, which checks that state and then redirects to `oidc.logout.redirect_to` (default `/`).

- **Register `{APP_URL}/auth/oidc/logged-out` at the IdP** as a post-logout redirect URI (`php artisan oidc:configure` prints it). **Until it is registered, logout does not end the IdP session:** Keycloak (and, as far as we know, other IdPs) refuses the whole end-session request with "Invalid redirect uri", so the next "Sign in with SSO" signs the user back in silently. Register it before deploying this release.
- Set `oidc.logout.redirect_to` to the page users should land on (for example `/login`).
- An app that sets `oidc.post_logout_redirect_uri`, or passes `postLogoutRedirectUri` from its own `ProviderConfigurationRepositoryContract`, keeps its URI. A URI other than the package route skips the state check; pass `route('oidc.logged-out')` there to keep the check.
- An app that owns its routes can leave the route out with `oidc.routes.except = ['oidc.logged-out']`; the default post-logout URI then falls back to `{APP_URL}/`.

## 1.0.0-beta.6 (from 1.0.0-beta.5)

- **Database:** recreate the package tables. The `user_identities` create migration gained the link snapshots, the last-login columns, `format_version` and `metadata`, and `oidc_logout_revocations` is a new table.
- Schedule `php artisan oidc:prune-logout-revocations` hourly.
- **Outbound:** see below.

### Adopting `qiick/laravel-outbound`

#### Composer

```bash
composer require qiick/laravel-oidc:^1.0@beta
# pulls qiick/laravel-outbound:^0.1 transitively
```

No separate outbound publish is required for OIDC. Keep using the OIDC config keys below.

#### Config (public keys unchanged unless noted)

| Key / env | Effect |
| --- | --- |
| `oidc.http.allow_private_hosts` / `OIDC_ALLOW_PRIVATE_HOSTS` | When `true`, private / loopback / link-local hosts and plain `http` are allowed together (lab / Docker IdPs). Cloud metadata stays blocked. Mapped onto outbound `UrlGuardOptions`. |
| `oidc.http.timeout` / `OIDC_HTTP_TIMEOUT` | Per-hop timeout for IdP calls (seconds, default `10`). **`0` still means no practical limit** (mapped to a 24h ceiling for outbound's ≥1s contract). |
| `oidc.http.connect_timeout` / `OIDC_HTTP_CONNECT_TIMEOUT` | **New (optional).** TCP connect timeout (seconds, default `10`, same as before). `0` means no practical limit. |
| `oidc.http.max_response_bytes` / `OIDC_MAX_RESPONSE_BYTES` | **New.** Cap on IdP response bodies (default `1048576`). |

Do not rely on `OUTBOUND_ALLOW_PRIVATE_HOSTS` for this package: OIDC builds its own guard / pinned client privately and maps `oidc.http.allow_private_hosts` onto the options it passes. Installing both packages does not let outbound's SSRF or timeout ceilings override IdP calls.

#### Removed

- `Qiick\Oidc\Services\RemoteUrlGuardService` — construct outbound's `Qiick\Outbound\Ssrf\RemoteUrlGuard` in tests if needed. `FakeIdentityProvider::fake()` only rebinds OIDC's private host resolver (`OidcOutboundStackFactory::HostResolverBinding` / `oidc.ssrf.host_resolver`), never the shared outbound singletons.

#### Behaviour

IdP HTTP still refuses redirects, still pins with `CURLOPT_CONNECT_TO`, and still fails closed on SSRF. Outbound additionally enforces response size limits on every IdP call.

**NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`) and Teredo (`2001::/32`) are now always blocked**, including when `OIDC_ALLOW_PRIVATE_HOSTS=true`. Previously those transition prefixes could be reached under the private-host opt-in; outbound's guard refuses them unconditionally so an IdP URL or DNS answer cannot tunnel to metadata or loopback through them.

## 1.0.0-beta.5 (from 1.0.0-beta.4)

The `2026_11_18` collation migration is folded into the `user_identities` create migration; the schema is unchanged. Delete the `migrations` row of the removed file (or recreate the database) to keep `migrate:status` clean. An app that published the migrations deletes the published `2026_11_18` file.

## 1.0.0-beta.4 and 1.0.0-beta.3

No action. IdP URLs that spell an IP address in decimal, octal, hex or short form are refused, and every server-side IdP call is pinned to the address the SSRF guard checked. With `OIDC_ALLOW_PRIVATE_HOSTS=true` a host name that nothing can resolve is refused, and the Alibaba Cloud and Oracle Cloud metadata addresses stay blocked.

## 1.0.0-beta.2 (from 1.0.0-beta.1)

- Run `php artisan migrate` (beta.5 folds this migration into the create migration).
- On MySQL and MariaDB, compare `user_identities` with the IdP's users if the IdP issues subjects that differ only in case: beta.1 matched them case-insensitively.
- A `sub` with leading or trailing whitespace is refused; a user linked under one must be linked again.
- Remove any app workaround that moved `EnsureOidcSessionIsActiveMiddleware` before `auth`: the package does it now.

## 1.0.0-beta.1

First install: `composer require qiick/laravel-oidc:^1.0@beta`, `php artisan vendor:publish --tag=oidc-config`, `php artisan migrate`, `php artisan oidc:configure`. Moving from the Socialite client copied in Externa and Excubia App: [`docs/MIGRATION.md`](./docs/MIGRATION.md). The defaults to announce (auto-link off, verified email required, no remember-me for SSO, SSO does not skip the app's 2FA) are in the README, "Security-relevant defaults".
