# Contributing to laravel-oidc

Thanks for helping. A few rules keep the codebase consistent:

1. Open or pick an issue first. One topic per pull request.
2. Branch from `develop` as `<type>/<kebab-slug>` (types: feat, fix, refactor, chore, docs, test, perf, ci, build, security).
3. Use Conventional Commits; PR titles follow the same format.
4. Open the PR against `develop`. PRs are squash-merged.
5. Before pushing run `composer test` (Pest), `composer lint` (Pint) and `composer analyse` (PHPStan).
6. Code style: strict types, explicit role suffixes, readonly `*Data` classes, English docblocks that explain *why*, no abbreviations.
7. Security checks are never weakened. A change to token validation, `state`, PKCE, redirects or the SSRF guard needs a test that proves a bad value is refused.
8. The package stays IdP-agnostic. Provider-specific behaviour goes behind config.
