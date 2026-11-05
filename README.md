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
```

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

## Development

```bash
composer install
composer test      # Pest + Testbench
composer lint      # Pint
composer analyse   # PHPStan, level max
```

Tests never use the network.

## Contributing and security

See [CONTRIBUTING.md](./CONTRIBUTING.md). Report vulnerabilities privately, as described in [SECURITY.md](./SECURITY.md).

## License

MIT. See [LICENSE](./LICENSE).
