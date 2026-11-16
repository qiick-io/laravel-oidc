# Changelog

All notable changes to **laravel-oidc** (`qiick/laravel-oidc`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Default `oidc.mfa.acr_values` is `['urn:qiick:loa:mfa']` so Signaculum MFA `acr` counts without extra config (pairs with signaculum-core #69). `urn:qiick:loa:pwd` is password-only and is not accepted as MFA.
- Documented L4 defaults (Decision Luca, 2026-11-13): `oidc.auto_link` off, `oidc.require_verified_email` on with per-provider opt-out, no remember-me for SSO, and 2FA after SSO via the app challenge when `amr`/`acr` are missing.

### Upgrade notes

- **`oidc.mfa.acr_values` now defaults to `['urn:qiick:loa:mfa']`.** Apps that relied on an empty list (accepting no `acr`) and only checked `amr` are unchanged in practice when Signaculum always sends `amr`. To ignore Signaculum `acr`, set `acr_values` back to `[]`.
- **Auto-link is off by default.** Existing apps that relied on always-on email linking must set `OIDC_AUTO_LINK=true` (or the equivalent settings key) after adopting the package, or import identities with `oidc:import-legacy-subjects`.
- **Verified email is required by default.** For Entra ID (no `email_verified`), set `oidc.require_verified_email` to `false` for that provider.
- **SSO does not set a remember-me cookie** (`oidc.remember` defaults to `false`). Enable only if you accept cookies that outlive IdP logout.
- **SSO does not skip app 2FA.** When the app requires a second factor and the `id_token` has no accepted `amr`/`acr`, the package hands over to the app's challenge (Fortify by default).

### Added

- Zitadel end-to-end Pest group (`zitadel`) and fixtures under `tests/Fixtures/zitadel/` (Docker `start-from-init` with Postgres, Management API seed). Role mapping accepts Zitadel's map-shaped `urn:zitadel:iam:org:project:roles` claim (keys are role names).
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
