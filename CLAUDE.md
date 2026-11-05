# CLAUDE.md — laravel-oidc (`qiick/laravel-oidc`)

Guidance for Claude Code in this repository. Read it fully before any change.

## Project

`qiick/laravel-oidc` is a generic OpenID Connect client for Laravel apps. It replaces the Socialite OIDC client that Externa (`qiick-io/externa-core`) and Excubia App (`qiick-io/excubia-app`) each carry as a copy, and adds what both copies miss: PKCE, nonce, `id_token` validation, logout, role mapping, SSO-only mode and MFA through `amr` / `acr`.

- Source of truth: the accepted design "2026-11-05 Signaculum SSO design" (knowledge base, `projects/qiick/research/`), sections 3 (protocol profile) and 4 (client behaviour). The README "Protocol profile" section is its summary in this repo.
- The package works with **any** standard IdP: Keycloak, Zitadel, Authentik, Entra ID, Google, Signaculum. Signaculum (`qiick-io/signaculum-core`) is one IdP among them. Everything Signaculum-specific (the `orgs` claim, the `qiick.orgs` scope) sits behind config or a mapping.
- The name is descriptive on purpose. No Latin product name, no "Signaculum" in class names or user-facing strings.
- If the design's wire contract looks wrong, tell Luca. Do not diverge silently.

## Stack

- PHP `^8.3`, Laravel 12 and 13 (`illuminate/*`).
- Dev: Pest 4 + Orchestra Testbench, Pint (pinned `<1.31`), PHPStan / Larastan at level max.
- No npm, no Vitest.

## Layout

```
config/oidc.php        defaults; env vars OIDC_* (see README)
routes/oidc.php        package routes under oidc.routes.prefix
src/Contracts/         *Contract interfaces (ProviderConfigurationRepositoryContract)
src/Data/              readonly *Data value objects
src/Enums/             *Enum
src/Exceptions/        *Exception, all extending OidcException
src/Http/              *Controller (back-channel logout) and *Middleware (session revocation)
src/Laravel/           OidcServiceProvider (auto-discovered)
src/Repositories/      *Repository (config-backed provider settings)
src/Services/          *Service (discovery, JWKS, JWT validation, code flow, SSRF guard, IdP HTTP)
src/Testing/           Fake* test doubles shipped for apps (FakeIdentityProvider)
tests/Arch             NamingArchitectureTest
tests/Feature          Pest on Testbench
tests/Support          PackageTestCase
```

## Commands

```bash
composer test      # Pest
composer lint      # Pint --test
composer analyse   # PHPStan
```

Run all three before every push. CI (`.github/workflows/ci.yml`) runs PHP 8.3/8.4/8.5 × lowest/stable and Laravel 12/13.

## Code conventions ("Codice Perfetto")

Also in `.cursor/rules/code-craftsmanship.mdc` and `.cursor/rules/testing.mdc`; follow them.

- Simplest thing that works (YAGNI), except at trust boundaries: token validation, `state`, PKCE, SSRF and redirects are never shortcut.
- `declare(strict_types=1);` in every PHP file. Role suffixes as enforced by the architecture test.
- Full words only. Booleans start with `is`, `has`, `can` or `should`. Curly braces always; a blank line around control-flow blocks.
- English PHPDoc on classes and non-trivial methods; cite the spec section behind each security check.
- Tests: no real network. Every security check has a test that proves a bad value is refused.
- Never log tokens, codes, secrets or full claim sets.

## Git and PR workflow

- Branch from `develop` as `<type>/<slug>`; Conventional Commits in English; PRs into `develop`, squash-merged.
- Merge only with Luca's explicit OK. Never push to `main`. No tags, releases or Packagist (`.cursor/rules/no-auto-release.mdc`).
- The repository is **private**. Never change its visibility.
- The GitHub token has no `workflow` scope: a push that adds or changes `.github/workflows/*` fails. Put workflow changes in their own commit and give Luca the push command.

## Identity and security

- Commit and push only as **LucaGiardi20**. Never run `gh auth switch`.
- Never use `--admin`, `--no-verify`, force-push to shared branches, or bypass branch protection.
- Never commit secrets, tokens, `.env` files, personal phone numbers or email addresses. Test keys are generated at test time.

## Ask Luca first

- Adding, removing or upgrading a Composer dependency; changing the PHP or Laravel floor.
- Changing a public contract (config keys, env vars, routes, the `user_identities` schema, events, the `oidc:configure` options) once released.
- Anything outside the design's scope, or work that needs secrets, accounts or paid services.
