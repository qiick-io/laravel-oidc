# Public API and deprecation policy

This is the public API of `qiick/laravel-oidc` that `1.0.0` freezes (packages 1.0 checklist, items 14 and 16). Everything listed here follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and the deprecation policy below. A class marked `@internal` can change or disappear in any release. `tests/Arch/PublicApiTest.php` checks class classification, config keys, environment variables and named routes against this page.

## Classes

An app may use these classes as described in the README. "Construct" means the app builds instances itself; the constructor signature is then public too.

| Class | Public as |
| --- | --- |
| `Laravel\OidcServiceProvider` | the auto-discovered service provider |
| `Contracts\BreakGlassPolicyContract` | contract an app binds |
| `Contracts\ProviderConfigurationRepositoryContract` | contract an app binds |
| `Contracts\RoleSynchronizationContract` | contract an app binds |
| `Contracts\SecondFactorChallengeContract` | contract an app binds |
| `Contracts\UserClaimSynchronizationContract` | contract an app binds |
| `Contracts\UserProvisioningContract` | contract an app binds |
| `Repositories\ConfigProviderConfigurationRepository` | default repository; an app may wrap it |
| `Services\AuthorizationCodeFlowService` | `redirect()`, `handleCallback()` |
| `Services\OidcLoginService` | `login()` |
| `Services\RpInitiatedLogoutService` | `endSessionUrl()` |
| `Services\SsoOnlyModeService` | `loginOptions()`, `canUseLocalLogin()` |
| `Services\UserLinkingService` | `resolve()`; apps construct it with named arguments |
| `Services\EloquentUserProvisioningService` | default `UserProvisioningContract` |
| `Services\FortifySecondFactorChallengeService` | default `SecondFactorChallengeContract`; apps construct it |
| `Services\RoleBreakGlassPolicyService` | default `BreakGlassPolicyContract` |
| `Services\SpatieRoleSynchronizationService` | default `RoleSynchronizationContract` |
| `Services\NullUserClaimSynchronizationService` | default `UserClaimSynchronizationContract` |
| `Data\AuthenticatedIdentityData` | read by apps (claims, `authTime()`, `acr()`, `amr()`, `personName()`) |
| `Data\ProviderConfigurationData` | apps construct it in their own repository |
| `Data\PersonNameData` | returned by `AuthenticatedIdentityData::personName()` |
| `Data\LoginOptionsData` | returned by `SsoOnlyModeService::loginOptions()` |
| `Enums\LoginRefusalReasonEnum` | cases and `message()` |
| `Enums\TokenEndpointAuthMethodEnum` | cases |
| `Erasure\OidcEraser` | resolved from the container; `erase()`, `DELETE`, `ANONYMISE` |
| `Erasure\ErasureReport` | read by apps; `changed()`, `toArray()` |
| `Erasure\OrganisationScopeUnsupportedException` | caught when an app requests organisation-scoped OIDC erasure |
| `Events\SubjectErasedEvent` | listened to by apps; carries the erasure report |
| `Events\OidcIdentityLinkedEvent`, `Events\OidcLoginSucceededEvent`, `Events\OidcUserProvisionedEvent`, `Events\OidcLogoutReceivedEvent` | listened to by apps |
| `Exceptions\OidcException`, `Exceptions\IdentityProviderRequestException`, `Exceptions\InvalidCallbackException`, `Exceptions\InvalidTokenException`, `Exceptions\LoginRefusedException`, `Exceptions\OidcNotConfiguredException` | caught by apps |
| `Models\UserIdentity`, `Models\OidcLogoutRevocation` | queried by apps; their tables are listed below |
| `Http\Controllers\*Controller` | route targets an app may register itself (see `oidc.routes.except`) |
| `Console\*Command` | through their command names and options only |
| `Testing\FakeIdentityProvider` | the in-memory IdP for app tests |

Every class name above is in the `Qiick\Oidc` namespace. Adding a trailing optional constructor parameter, a method or a class is not a breaking change.

## Configuration and environment

Config keys (all under `oidc.`): `enabled`, `issuer`, `client_id`, `client_secret`, `button_label`, `jit`, `auto_link`, `only`, `redirect_uri`, `allowed_domains`, `require_verified_email`, `remember`, `home`, `login_url`, `users.model`, `users.table`, `users.email_column`, `users.active_column`, `break_glass.roles`, `break_glass.require_two_factor`, `break_glass.query_parameter`, `roles.enabled`, `roles.claim`, `roles.organization`, `roles.map`, `roles.forbidden`, `mfa.required`, `mfa.trust_provider`, `mfa.amr_values`, `mfa.acr_values`, `mfa.request_acr_values`, `mfa.max_age`, `mfa.require_requested_acr`, `post_logout_redirect_uri`, `logout.redirect_to`, `userinfo`, `routes.enabled`, `routes.prefix`, `routes.middleware`, `routes.except`, `backchannel_logout.schedule`, `backchannel_logout.rate_limit`, `backchannel_logout.revocation_ttl`, `backchannel_logout.max_retention_seconds`, `frontchannel_logout.enabled`, `scopes`, `token_endpoint_auth_method`, `id_token.algorithms`, `id_token.leeway`, `id_token.trusted_audiences`, `cache.store`, `cache.discovery_ttl`, `cache.jwks_ttl`, `cache.jwks_refetch_cooldown`, `http.timeout`, `http.connect_timeout`, `http.max_response_bytes`, `http.discovery_base`, `http.server_origin`, `http.allow_private_hosts`.

Environment variables: `OIDC_ENABLED`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_BUTTON_LABEL`, `OIDC_JIT`, `OIDC_AUTO_LINK`, `OIDC_ONLY`, `OIDC_FRONTCHANNEL_LOGOUT`, `OIDC_HTTP_TIMEOUT`, `OIDC_HTTP_CONNECT_TIMEOUT`, `OIDC_MAX_RESPONSE_BYTES`, `OIDC_DISCOVERY_BASE`, `OIDC_SERVER_ORIGIN`, `OIDC_ALLOW_PRIVATE_HOSTS`.

A key added in a minor release always has a default, and a config file published before it keeps working (the package reads it with a default).

## Routes, commands, events and tables

| Name | Method | Default URI |
| --- | --- | --- |
| `oidc.redirect` | `GET` | `/auth/oidc/redirect` |
| `oidc.callback` | `GET` | `/auth/oidc/callback` |
| `oidc.backchannel-logout` | `POST` | `/auth/oidc/backchannel-logout` |
| `oidc.frontchannel-logout` | `GET` | `/auth/oidc/frontchannel-logout` |
| `oidc.logged-out` | `GET` | `/auth/oidc/logged-out` |

`oidc.routes.prefix` changes the path prefix. `oidc.routes.except` excludes individual routes by name so an app can register its own handler. `oidc.routes.enabled` controls registration of all five routes. The front-channel endpoint returns `404` unless the feature is enabled.

- Commands: `oidc:check` (exit code), `oidc:configure` (`--issuer`, `--client-id`, `--client-secret`, `--write-env`, `--json`, and the JSON report keys), `oidc:import-legacy-subjects` (`--column`, `--issuer`, `--dry-run`), `oidc:prune-logout-revocations` (`--chunk`, `--dry-run`).
- Events: the five event classes above, with their public properties.
- Tables: `user_identities` and `oidc_logout_revocations`, as created by the package migrations. After `1.0.0` the migrations are forward-only and additive.
- Reserved identity columns: `user_identities.subject_type` and `user_identities.provider_key` default to `NULL`. Package login and import leave them `NULL` until the [multi-provider registry work (L4)](./decisions/2026-11-22-defer-provider-registry.md).
- Back-channel protocol errors use HTTP `400` with `error: invalid_request` and `error_description`. Over-budget rejections use HTTP `429` with `error: too_many_requests` and `Retry-After`.
- Session keys (`oidc.identity`, `oidc.pending_identity`, `oidc.pending_logins`) and cache keys are internal.

## Deprecation policy

- A **patch** release fixes bugs and security issues. It never removes or renames anything public, and changes behaviour only to fix a defect or close a security gap, with an upgrade note in the CHANGELOG.
- A **minor** release may add public API and may **deprecate** it: the item keeps working, gets a `@deprecated` tag naming its replacement and the version that deprecated it, and the CHANGELOG lists it under "Deprecated". A deprecated config key or env var keeps being read; where the replacement exists, the package reads both and the new one wins.
- Only a **major** release removes or renames public API, changes a public signature incompatibly, or changes a default in a way an app must react to. `UPGRADING.md` describes every such change.
- Security is the exception: if keeping a public behaviour would leave apps open to an attack, a minor or patch release may change it, with a "Security" entry in the CHANGELOG and an upgrade note.
- Before `1.0.0` (the betas), breaking changes may land in any release; each one is listed under "Upgrade notes" in the CHANGELOG and in `UPGRADING.md`.
