# Changelog

All notable changes to **laravel-oidc** (`qiick/laravel-oidc`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Package skeleton: auto-discovered `OidcServiceProvider`, publishable `config/oidc.php` (tag `oidc-config`) with the env vars `OIDC_ENABLED`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_BUTTON_LABEL`, `OIDC_JIT`, `OIDC_AUTO_LINK` and `OIDC_ONLY`; Pest + Testbench, Pint, PHPStan at level max, an architecture test.
