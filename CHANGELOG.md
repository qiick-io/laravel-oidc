# Changelog

All notable changes to **laravel-oidc** (`qiick/laravel-oidc`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Package skeleton: auto-discovered `OidcServiceProvider`, publishable `config/oidc.php` (tag `oidc-config`) with the env vars `OIDC_ENABLED`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_BUTTON_LABEL`, `OIDC_JIT`, `OIDC_AUTO_LINK` and `OIDC_ONLY`; Pest + Testbench, Pint, PHPStan at level max, an architecture test.
- Protocol layer (#2): discovery with exact issuer match, PKCE `S256` and code-flow checks, cached for 6 hours; the authorization code flow with PKCE `S256`, `state` and `nonce` (pending logins in the session, single use, 10 minutes, up to 5 tabs), RFC 9207 `iss` check, `client_secret_basic`, `client_secret_post` and public clients; `id_token` validation (asymmetric `alg` allowlist, JWKS signature with cached keys and a rate-limited refetch on an unknown `kid`, `iss`, `aud` with trusted extra audiences, `azp`, `exp`, `iat`, `nbf`, `sub`, `nonce`).
- SSRF guard ported from Externa for every server-side IdP call (https only, no private, loopback, CGNAT or metadata addresses, DNS pinning, no redirects), with the Docker settings `OIDC_DISCOVERY_BASE`, `OIDC_SERVER_ORIGIN` and `OIDC_ALLOW_PRIVATE_HOSTS`.
- `ProviderConfigurationRepositoryContract`, so an app can serve the settings from its database.
- `Qiick\Oidc\Testing\FakeIdentityProvider`: an in-memory IdP for tests, in this package and in the apps.
