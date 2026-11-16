# Security Policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| `1.0.0-beta.1` | Yes, for this pre-release line. |
| Older pre-releases / untagged `develop` | No. |

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting ("Report a vulnerability" on the Security tab of `qiick-io/laravel-oidc`). We aim to acknowledge reports within 72 hours.

This package is an authentication boundary. Reports about token validation (`id_token`, `logout_token`), `state`, `nonce`, PKCE, open redirects, account linking, role mapping or SSRF through discovery are treated as critical.
