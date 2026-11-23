# Changelog

All notable changes to **laravel-oidc** (`qiick/laravel-oidc`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- A `sub`-only back-channel logout received while the app's second factor was pending no longer stops matching once the challenge completes: promotion keeps the callback time as the session's `authenticated_at`.

### Added

- `oidc:configure` warns when `app.timezone` is not `UTC`, and the README documents that the package's timestamps are UTC (standards review M7).

### Fixed

- `oidc:configure` treats an `http://[::1]` redirect URI as local instead of warning about plain http on a public host.

### Documentation

- README brought up to beta.6: version, the `oidc_logout_revocations` table as the source of truth with the prune schedule, front-channel logout setup, `oidc.routes.except`, and the supported `id_token` algorithms.

## [1.0.0-beta.6] - 2026-11-22

### Upgrade notes

- **Requires `qiick/laravel-outbound:^0.1`.** Server-side IdP calls (discovery, JWKS, token, userinfo) now go through outbound's `RemoteUrlGuard` and `PinnedHttpClient`. The local `RemoteUrlGuardService` is removed. Public config keys are unchanged: `oidc.http.allow_private_hosts` / `OIDC_ALLOW_PRIVATE_HOSTS` still allow private hosts and plain http together; cloud metadata stays blocked. Optional `oidc.http.max_response_bytes` / `OIDC_MAX_RESPONSE_BYTES` (default 1 MiB) caps IdP response bodies. `oidc.http.timeout=0` still means no practical limit; optional `oidc.http.connect_timeout` defaults to 10s. See `UPGRADING.md`.
- **Recreate beta databases (`php artisan migrate:fresh`).** The package is not stable yet, so schema changes edit or add `create_…` migrations instead of forward alters. This release:
  - enriches `2026_11_05_000000_create_user_identities_table` with public id, link/email snapshots, last-login auth metadata, `format_version` and `metadata` (#57);
  - adds `2026_11_22_000000_create_oidc_logout_revocations_table` for durable back-/front-channel logout `jti` storage (#60).
  Existing installs that already ran an older create migration will not pick up those columns or the new table from a plain `migrate`. Fresh installs are fine. Apps that published the migrations (`vendor:publish --tag=oidc-migrations`) publish again after updating.

### Added

- Enriched `user_identities` create migration and model casts for public id, link method, email/username/name snapshots, last-login `auth_time` / `acr` / `amr` / `id_token` alg, `format_version` and `metadata` (#57).
- SSO login writes those identity columns and calls `UserClaimSynchronizationContract` after role mapping (#58).
- Versioned SSO session payload (`format_version` 1 with `acr` / `amr` / `auth_time`); unknown versions fail closed and end the local session (#59).
- Durable `oidc_logout_revocations` store: unique `(issuer, jti)`, fail-closed table reads, cache as accelerator only, `oidc:prune-logout-revocations` (#60).
- `at_hash` validation against the access token when present on the `id_token` (OIDC Core 3.1.3.8 / 3.2.2.9) (#61).
- `oidc.routes.except` to skip selected package routes, and optional `GET …/frontchannel-logout` behind `oidc.frontchannel_logout.enabled` (#62).
- Real-transport Pest group against `php -S` on Guzzle 7 and 8 (CI job `real-transport`).
- Per-class mutation gate for `IdentityProviderHttpService`, `DiscoveryService` and `OidcOutboundStackFactory` (≥95%, no `--covered-only`).

### Changed

- **SSRF and pinned HTTP are delegated to `qiick/laravel-outbound`.** Behaviour is not loosened: every previous SSRF refusal remains a refusal, CONNECT_TO pinning remains, redirects stay off on the IdP path, and outbound adds response size limits plus cross-origin redirect credential stripping when redirects are opted in (tests cover the wire). OIDC builds its own guard / client privately so `OutboundServiceProvider` cannot override IdP SSRF or timeouts. NAT64, 6to4 and Teredo are always blocked (see `UPGRADING.md`).

## [1.0.0-beta.5] - 2026-11-22

### Upgrade notes

- **The case-sensitive identity key is now part of the create migration.** `2026_11_18_000000_make_user_identity_keys_case_sensitive` is folded into `2026_11_05_000000_create_user_identities_table`, which now creates `issuer` and `subject` with `utf8mb4` / `utf8mb4_bin` on MySQL and MariaDB directly. The package is not stable yet, so its schema changes edit the create migration instead of adding new ones. The final schema is unchanged.
  - **Fresh installs** get the same schema in one migration.
  - **Existing databases that already ran beta.2 to beta.4** already have that schema. The `migrations` table keeps a row for the removed file, which is harmless. Delete that row, or recreate the database (`migrate:fresh`), to keep `migrate:status` clean.
  - **Apps that published the migrations** (`vendor:publish --tag=oidc-migrations`) delete the published `2026_11_18` file and publish again.

## [1.0.0-beta.4] - 2026-11-20

### Security

- **The Alibaba Cloud (`100.100.100.200`) and Oracle Cloud (`192.0.0.192`) instance metadata addresses stay blocked with `OIDC_ALLOW_PRIVATE_HOSTS=true`.** Both fall in ranges the guard already blocks by default, but opting into a private-lab IdP made them reachable: a discovery document, issuer URL or resolver answer naming either address could reach the metadata service. Every spelling the guard canonicalises is covered too — decimal, octal, hex, short, trailing-dot, IPv4-mapped and IPv4-compatible forms. Legitimate IdP endpoints are unchanged. Mirrors qiick-io/signaculum-core#190.

## [1.0.0-beta.3] - 2026-11-19

### Upgrade notes

- **Outbound IdP URLs that are not a hostname or dotted-decimal / canonical IP are now refused.** Decimal, octal, hex and short IPv4 spellings (`2852039166`, `0251.0376.0251.0376`, `0xa9.0xfe.0xa9.0xfe`, `169.254.43518`), a trailing root dot on an address (`169.254.169.254.`), and a bracketed host that is not a valid IPv6 literal are rejected before any request. Legitimate discovery, token, JWKS, userinfo and end-session URLs are unchanged. With `OIDC_ALLOW_PRIVATE_HOSTS=true`, a hostname that neither DNS nor the system resolver can answer is also refused (previously authorised unpinned). Cloud metadata stays blocked even when private hosts are allowed, including when a name resolves to `169.254.169.254` / `fd00:ec2::254`.

### Security

- **Every server-side IdP call is pinned to one address the SSRF guard checked**, through `CURLOPT_CONNECT_TO` `::ADDRESS:PORT`, never `CURLOPT_RESOLVE`. `filter_var()` rejects alternate IPv4 spellings that curl and `inet_aton(3)` still read as addresses (for example `2852039166` = `169.254.169.254`); with the old pin those hosts went out unpinned or with a RESOLVE entry curl ignores, so a lab setting or a resolver that answers could reach the metadata service. The guard now reads IPv4 the way curl does, canonicalises IPv6 and IPv4-mapped/compatible forms, refuses unresolved names, and pins every authorised destination. Ported from qiick-io/signaculum-core#189.

## [1.0.0-beta.2] - 2026-11-18

### Upgrade notes

- **Run `php artisan migrate` after updating.** The new migration `2026_11_18_000000_make_user_identity_keys_case_sensitive` changes `user_identities.issuer` and `subject` to `utf8mb4` / `utf8mb4_bin` on MySQL and MariaDB; on PostgreSQL and SQLite it does nothing. The `2026_11_05` create migration is unchanged, because beta.1 is released and migrations are forward-only. An app that published the migrations (`vendor:publish --tag=oidc-migrations`) publishes again to get the new file. The change cannot fail on existing rows: the old case-insensitive unique index could never hold two keys that differ only in case.
- **A beta.1 install on MySQL or MariaDB should check its links after migrating.** Before this release, a login whose `sub` differed only in case from a linked one signed in as that linked user, and an auto-link or JIT login for such a `sub` failed on the unique index. Nothing in the table records that this happened, so compare `user_identities` with the IdP's users if an IdP issues mixed-case subjects.
- **An `id_token` or `logout_token` whose `sub` has leading or trailing whitespace is now refused** (logged as `OIDC login failed: id_token [sub] has leading or trailing whitespace.`). No standard IdP issues one; a user linked under such a `sub` cannot sign in until the identity is relinked.

### Security

- **The identity key (`issuer`, `sub`) is now compared case-sensitively on MySQL and MariaDB.** `user_identities.subject` was a plain `string` column, so it took the table's collation, which is case-insensitive in every usual setup: Laravel's default `utf8mb4_unicode_ci`, or the server default (`utf8mb4_0900_ai_ci` on MySQL 8.4, `utf8mb4_general_ci` on MariaDB 10.11). An OIDC `sub` is opaque and case-sensitive (OIDC Core 2), so two subjects of one issuer that differ only in case were one identity: the login of `abcsubject` signed in the user linked to `AbcSubject`, and the unique index refused to store the second identity. A forward migration sets the binary collation `utf8mb4_bin` on `issuer` and `subject` for the MySQL family. Found by the adoption in qiick-io/excubia-app#357.
- **A `sub` with leading or trailing whitespace is refused** where it enters the package, in the `id_token` and in the `logout_token`. `utf8mb4_bin` is PAD SPACE on both engines, so `AbcSubject ` still equalled `AbcSubject` after the collation change; the NO PAD binary collations have a different name on each engine, so the portable fix is to refuse the `sub` before any lookup, on every database. The refusal goes through the usual `InvalidTokenException` path, which logs a warning.

### Added

- CI runs the Pest suite on MySQL 8.4, MariaDB 10.11 and PostgreSQL 17 as well as SQLite (job `databases`); the test case uses the connection named by `DB_CONNECTION` in the process environment.

### Fixed

- **Security: the back-channel logout check now runs before `auth`, not after.** The service provider appended `EnsureOidcSessionIsActiveMiddleware` to the `web` group, but Laravel's middleware priority list reorders a group and places anything it does not name after everything it does — and `AuthenticatesRequests` is named. So `auth` ran first, and the first request after a back-channel logout passed `auth` as an authenticated user and reached the controller with a session the identity provider had already ended. The middleware is now inserted with `addToMiddlewarePriorityBefore(AuthenticatesRequests::class, …)`: after `StartSession`, which it needs in order to see the SSO identity, and before `auth`, which its own contract requires. Two regression tests pin it — a route behind `auth`, and the resolved order `StartSession < check < auth`. Found by the first real adoption of the package (qiick-io/instituta-core#355), which had worked around it in its own `bootstrap/app.php`; that workaround can be removed (#35).

### Changed

- `composer.json` no longer carries a hardcoded `"version"`. Packagist derives the version from the git tag, so the field was redundant and would have been able to disagree with a later tag with no test objecting (#31).
- The qiick standards pack is pinned to **app-ui v0.9.0** instead of tracking its `develop` branch. A drift check that follows a moving branch passes because the target moved, not because the repository is aligned (#34).


## [1.0.0-beta.1] - 2026-11-16

First public beta of `qiick/laravel-oidc`: a generic OpenID Connect client for Laravel 12 and 13 (PHP `^8.3`).

### Upgrade notes

- **First install:** `composer require qiick/laravel-oidc:^1.0@beta`, then `php artisan vendor:publish --tag=oidc-config`, `php artisan migrate`, and `php artisan oidc:configure`. Prefer `@beta` until `1.0.0` is tagged.
- **`oidc.mfa.acr_values` defaults to `['urn:qiick:loa:mfa']`.** Apps that relied on an empty list (accepting no `acr`) and only checked `amr` are unchanged in practice when Signaculum always sends `amr`. To ignore Signaculum `acr`, set `acr_values` back to `[]`.
- **Auto-link is off by default.** Existing apps that relied on always-on email linking must set `OIDC_AUTO_LINK=true` (or the equivalent settings key) after adopting the package, or import identities with `oidc:import-legacy-subjects`.
- **Verified email is required by default.** For Entra ID (no `email_verified`), set `oidc.require_verified_email` to `false` for that provider.
- **SSO does not set a remember-me cookie** (`oidc.remember` defaults to `false`). Enable only if you accept cookies that outlive IdP logout.
- **SSO does not skip app 2FA.** When the app requires a second factor and the `id_token` has no accepted `amr`/`acr`, the package hands over to the app's challenge (Fortify by default).
- **Migrating from the copied Socialite client:** follow [`docs/MIGRATION.md`](./docs/MIGRATION.md).

### Changed

- Default `oidc.mfa.acr_values` is `['urn:qiick:loa:mfa']` so Signaculum MFA `acr` counts without extra config (pairs with signaculum-core #69). `urn:qiick:loa:pwd` is password-only and is not accepted as MFA.
- Documented L4 defaults (Decision Luca, 2026-11-13): `oidc.auto_link` off, `oidc.require_verified_email` on with per-provider opt-out, no remember-me for SSO, and 2FA after SSO via the app challenge when `amr`/`acr` are missing.

### Added

- Signaculum end-to-end Pest group (`signaculum`) and fixtures under `tests/Fixtures/signaculum/` (CI job `signaculum`, L2).
- Zitadel end-to-end Pest group (`zitadel`) and fixtures under `tests/Fixtures/zitadel/` (Docker `start-from-init` with Postgres, Management API seed; CI job `zitadel`, L3). Role mapping accepts Zitadel's map-shaped `urn:zitadel:iam:org:project:roles` claim (keys are role names).
- Signaculum wire-contract fixtures for discovery and `logout_token` claims aligned with `signaculum-core/docs/oidc-profile.md` (L1).
- Package skeleton: auto-discovered `OidcServiceProvider`, publishable `config/oidc.php` (tag `oidc-config`) with the env vars `OIDC_ENABLED`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_BUTTON_LABEL`, `OIDC_JIT`, `OIDC_AUTO_LINK` and `OIDC_ONLY`; Pest + Testbench, Pint, PHPStan at level max, an architecture test.
- Protocol layer (#2): discovery with exact issuer match, PKCE `S256` and code-flow checks, cached for 6 hours; the authorization code flow with PKCE `S256`, `state` and `nonce` (pending logins in the session, single use, 10 minutes, up to 5 tabs), RFC 9207 `iss` check, `client_secret_basic`, `client_secret_post` and public clients; `id_token` validation (asymmetric `alg` allowlist, JWKS signature with cached keys and a rate-limited refetch on an unknown `kid`, `iss`, `aud` with trusted extra audiences, `azp`, `exp`, `iat`, `nbf`, `sub`, `nonce`).
- SSRF guard ported from Externa for every server-side IdP call (https only, no private, loopback, CGNAT or metadata addresses, DNS pinning, no redirects), with the Docker settings `OIDC_DISCOVERY_BASE`, `OIDC_SERVER_ORIGIN` and `OIDC_ALLOW_PRIVATE_HOSTS`.
- `ProviderConfigurationRepositoryContract`, so an app can serve the settings from its database.
- `Qiick\Oidc\Testing\FakeIdentityProvider`: an in-memory IdP for tests, in this package and in the apps.
- Userinfo (#3): fetched after the code exchange with the access token, `sub` must match the `id_token`, claims merged under the signed `id_token` claims; `oidc.userinfo` turns it off.
- RP-initiated logout (#3): `IdentitySessionService` keeps the SSO identity (issuer, `sub`, `sid`, `id_token`) in the session; `RpInitiatedLogoutService::endSessionUrl()` builds the `end_session_endpoint` URL with `id_token_hint`, `client_id` and `post_logout_redirect_uri` (`oidc.post_logout_redirect_uri`).
- Back-channel logout (#3): `POST /auth/oidc/backchannel-logout` (`oidc.routes.*`) validates the `logout_token` (shared JWT checks, logout `events`, no `nonce`, `sub` or `sid`, single-use `jti`) and records it; `EnsureOidcSessionIsActiveMiddleware`, appended to the `web` group, ends the matching local sessions on their next request (`oidc.backchannel_logout.revocation_ttl`).
- SSO login (#4): `user_identities` table keyed by (`issuer`, `subject`) and the `UserIdentity` model; `UserLinkingService` (linked identity, per-provider auto-link by verified email, JIT with `oidc.allowed_domains`, inactive users refused, `LoginRefusedException` with `LoginRefusalReasonEnum`); `UserProvisioningContract` with an Eloquent default; `OidcLoginService` (default guard, session regenerated, identity kept for logout, remember-me only with `oidc.remember`); routes `oidc.redirect` and `oidc.callback`; events `OidcIdentityLinkedEvent`, `OidcUserProvisionedEvent`, `OidcLoginSucceededEvent`; config `require_verified_email`, `allowed_domains`, `remember`, `home`, `login_url`, `users.*`, `routes.middleware`.
- Back-channel logout cycles the remember token of the linked user (#4), so a remember-me cookie cannot outlive the logout.
- Role mapping (#5): `RoleMappingService` maps the IdP roles (Signaculum `orgs` for the configured `organization`, or a flat role claim at any path) to app roles at every login, before the user is signed in. Only roles named in `oidc.roles.map` are granted or revoked; `super-admin` and `oidc.roles.forbidden` are never granted; without the claim, local roles stay as they are. `RoleSynchronizationContract` with a spatie/laravel-permission default.
- MFA through `amr` / `acr` (#5): when the app requires 2FA (`SecondFactorChallengeContract`, default `oidc.mfa.required`) and the `id_token` shows no accepted `amr` (`oidc.mfa.amr_values`, default `mfa`) or `acr`, the callback hands over to the app's challenge (Laravel Fortify by default); `PromotePendingIdentityListener` completes the SSO session on the following `Login` event. `amr`, `acr` and the other protocol claims are no longer taken from userinfo. `oidc.mfa.request_acr_values` sends `acr_values`. `OidcLoginService::login()` now returns the challenge response or `null`.
- SSO-only mode (#6): `SsoOnlyModeService` (active only while SSO is configured), `canUseLocalLogin()` for app login callbacks, `loginOptions()` for the login page (password form hidden unless `?local=1`); `EnforceSsoOnlyListener` refuses password logins through `Auth::attempt()`; `BreakGlassPolicyContract` with a default of `oidc.break_glass.roles` plus a confirmed second factor.
- `php artisan oidc:configure` (#6): checks settings, discovery, end session, algorithms, JWKS, client, redirect URI and (SSO-only) the break-glass account; prints the URIs to register at the IdP; `--json`, `--write-env`; exit code 1 on any failure.
- Laravel Boost guidelines for agents that set the package up (#6).
- `php artisan oidc:import-legacy-subjects` (#7): copies `users.oidc_sub` into `user_identities` with the configured issuer; idempotent, `--dry-run`, conflicts reported and never moved.
- End-to-end tests against Keycloak 26 (#7): login through the real login form (PKCE, RFC 9207 `iss`, `id_token`, userinfo, JIT, realm-role mapping), RP-initiated logout ending the Keycloak session, a wrong client secret, and `oidc:configure`; CI job `keycloak`, group `keycloak` excluded from the default run.
- `docs/MIGRATION.md` (#7): step-by-step migration of Externa and Excubia App from their copied Socialite client.
- `AuthenticatedIdentityData::personName()` and `PersonNameData` (#13): given and family name from `given_name` / `family_name`, or from `name` split with the last word as the family name, for apps with `first_name` / `last_name` columns (agreed with Signaculum, whose `profile` scope now sends `given_name`, `family_name` and `locale`). The default JIT provisioning falls back to `given_name` + `family_name` when the IdP sends no `name`; `FakeIdentityProvider` emits both claims.

### Dependencies

- PHP `^8.3`, Laravel 12 and 13 (`illuminate/support`, `illuminate/http`, `illuminate/cache`), `firebase/php-jwt` `^7.0`, `guzzlehttp/guzzle` `^7.8 || ^8.0` (Guzzle 8 allowed since #10; Laravel 13 accepts it, Laravel 12 stays on Guzzle 7).

[Unreleased]: https://github.com/qiick-io/laravel-oidc/compare/v1.0.0-beta.6...HEAD
[1.0.0-beta.6]: https://github.com/qiick-io/laravel-oidc/compare/v1.0.0-beta.5...v1.0.0-beta.6
[1.0.0-beta.5]: https://github.com/qiick-io/laravel-oidc/compare/v1.0.0-beta.4...v1.0.0-beta.5
[1.0.0-beta.4]: https://github.com/qiick-io/laravel-oidc/compare/v1.0.0-beta.3...v1.0.0-beta.4
[1.0.0-beta.3]: https://github.com/qiick-io/laravel-oidc/compare/v1.0.0-beta.2...v1.0.0-beta.3
[1.0.0-beta.2]: https://github.com/qiick-io/laravel-oidc/compare/v1.0.0-beta.1...v1.0.0-beta.2
[1.0.0-beta.1]: https://github.com/qiick-io/laravel-oidc/releases/tag/v1.0.0-beta.1
