# OpenID Foundation conformance (Relying Party)

The package is tested as an **OpenID Connect Relying Party (RP)** with the self-hosted [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite). In the RP plans the suite plays the OpenID Provider: it serves discovery, JWKS, token and userinfo endpoints and hands the RP broken tokens, and the RP must refuse them. This page records which plans apply, the latest results, how to re-run them, a CI job proposal, and what formal certification would take. The harness files live in [`conformance/`](../../conformance).

The OpenID Provider side (Signaculum) has its own page: `docs/conformance/openid.md` in `qiick-io/signaculum-core`.

## Which plans apply

| Certification profile    | Suite plan (variant)                                                                                                                                     | Applies? | Why                                                         |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------------------------- |
| Basic RP                 | `oidcc-client-basic-certification-test-plan[client_registration=static_client][request_type=plain_http_request]`                                         | yes      | authorization code flow with PKCE, `client_secret_basic`    |
| Config RP                | `oidcc-client-config-certification-test-plan[client_auth_type=client_secret_basic][client_registration=static_client][request_type=plain_http_request]`  | yes      | discovery, JWKS, key rotation                               |
| RP-Initiated Logout RP   | `oidcc-client-rp-initiated-logout-rp-basic[…same variants…]`                                                                                             | yes      | `end_session_endpoint` with `id_token_hint` and `state`     |
| Back-Channel Logout RP   | `oidcc-client-back-channel-logout-rp-basic[…same variants…]`                                                                                             | yes      | signed `logout_token` at `auth/oidc/backchannel-logout`     |
| Front-Channel Logout RP  | `oidcc-client-front-channel-logout-rp-basic[…same variants…]`                                                                                            | yes      | `auth/oidc/frontchannel-logout` (behind its config switch)  |
| Dynamic RP               | `oidcc-client-dynamic-certification-test-plan`                                                                                                           | no       | the package uses a static client; no dynamic registration   |
| Implicit / Hybrid / Form Post RP | `oidcc-client-implicit-*`, `-hybrid-*`, `-formpost-*`                                                                                            | no       | code flow only                                              |
| Session Management RP    | `oidcc-client-rp-session-management-*`                                                                                                                   | no       | no `check_session_iframe` support                           |

## Results (2026-11-27, suite `release-v5.1.43`, `develop` at `3d40a90`)

| Plan                    | Modules | Passed | Review | Skipped | Failed | Result             |
| ----------------------- | ------- | ------ | ------ | ------- | ------ | ------------------ |
| Basic RP                | 14      | 13     | 0      | 1       | 0      | pass               |
| Config RP               | 6       | 5      | 0      | 1       | 0      | pass               |
| RP-Initiated Logout RP  | 3       | 0      | 3      | 0       | 0      | pass, needs review |
| Back-Channel Logout RP  | 8       | 8      | 0      | 0       | 0      | pass               |
| Front-Channel Logout RP | 1       | 0      | 1      | 0       | 0      | pass, needs review |

No module failed and none warned, so no `[conformance]` issue was opened for this package.

- **Skipped:** `oidcc-client-test-idtoken-sig-none` (in Basic and Config). The RP refuses an unsigned `alg: none` `id_token` ("Token signing algorithm is not allowed"), which the suite records as an allowed skip. `run-test-plan.py` still exits 1 for that unexpected skip unless you pass it an `--expected-skips-file`.
- **Review:** the logout modules end after the suite sees the end-session request, the back-channel call or the front-channel iframe. What the RP did with it is shown by the RP's own evidence: the harness's `rp-evidence.log` and the app's Laravel log. A person attaches that evidence for certification. In this run the RP signed out locally, followed the post-logout redirect, and logged `OIDC post-logout return without a matching state` for the `other-state` module.
- **Refusals logged by the RP** (each module where the suite expects a refusal): wrong `iss`, missing `sub`, wrong `aud`, missing `iat`, bad RS256 signature, `alg: none`, userinfo `sub` mismatch, wrong `nonce`, and discovery `issuer` mismatch. The multiple-keys-without-`kid` case is refused too, which the module allows. Back-channel `logout_token`s are refused for `alg: none`, a wrong algorithm, a missing or wrong `events` claim, a `nonce`, a wrong `aud` and a wrong `iss`.
- `oidcc-client-test-signing-key-rotation` and `-just-before-signing` are skipped by the suite's `run-test-plan.py` (it cannot automate them). `conformance/run-key-rotation.py` creates them through the suite API on the Config RP plan. Both passed: the RP refetched the rotated JWKS.

### What the harness does differently from an application

- **One linked user.** The suite's user has `email_verified: false`. JIT provisioning and auto-linking refuse that by design, so `conformance/harness/seed.php` links the suite's `sub` to a local user (step 1 of the linking rules).
- **Cache flush per module.** Every suite module publishes new signing keys at the same issuer within seconds. The package caches the JWKS and refetches on an unknown `kid` at most once per `oidc.cache.jwks_refetch_cooldown` (30 s), so `/harness/reset` clears the cache before each module. The key-rotation modules run without that reset, and they pass.
- **Discovery-only modules.** `oidcc-client-test-discovery-openid-config` and `-jwks-uri-keys` finish as soon as discovery and the JWKS are fetched. The driver calls `/harness/discover`, which fetches them through `DiscoveryService` and `JwksService`, instead of a full login, which the finished module would report as an illegal state change.
- **TLS.** The suite's certificate is issued to `localhost`. The RP container forwards `localhost:8443` to the suite and trusts that certificate through `curl.cainfo`, and `OIDC_DISCOVERY_BASE` / `OIDC_SERVER_ORIGIN` point server-side calls there while the issuer stays `https://nginx:8443/...`. Certificate checks are never switched off.

## Re-running the plans locally

Prerequisites: Docker. Everything runs in containers on the suite's Compose network; nothing listens on a public interface.

1. **Suite.** Clone `https://gitlab.com/openid/conformance-suite.git` at a release tag (this run: `release-v5.1.43`) and build it in a container with a named Maven volume:
   `docker run --rm -v oidf-m2:/root/.m2 -v "$PWD":/src -w /src maven:3-eclipse-temurin-21 mvn -B -q -DskipTests package`.
2. **Harness app.** Next to this checkout (a directory named `laravel-oidc`): `composer create-project laravel/laravel rp-app`, then in `rp-app`: `composer config repositories.oidc path ../laravel-oidc`, `composer require "qiick/laravel-oidc:*@dev"`, `php artisan vendor:publish --tag=oidc-config`, set `APP_URL=http://rp:8000` in `.env`, copy `conformance/harness/web.php` over `routes/web.php`, and copy `conformance/harness/seed.php` to the app root.
3. **Start**, from the suite directory, with the absolute paths exported:

    ```bash
    export LARAVEL_OIDC_DIR=/path/to/laravel-oidc RP_APP_DIR=/path/to/rp-app RESULTS_DIR=/path/to/results RP_ALIAS=rp-basic
    docker compose -p oidf -f docker-compose-localtest.yml -f "$LARAVEL_OIDC_DIR/conformance/docker-compose.rp.yml" \
      up -d mongodb nginx server chrome runner rp
    ```

4. **Run a plan** (restart `rp` with the matching `RP_ALIAS` between plans, `up -d rp`):

    ```bash
    docker exec oidf-runner-1 sh /laravel-oidc/conformance/run-rp-plan.sh rp-basic \
      "oidcc-client-basic-certification-test-plan[client_registration=static_client][request_type=plain_http_request]"
    docker exec oidf-runner-1 sh /laravel-oidc/conformance/run-rp-plan.sh rp-config \
      "oidcc-client-config-certification-test-plan[client_auth_type=client_secret_basic][client_registration=static_client][request_type=plain_http_request]"
    # logout plans: fourth argument 1 (log in and out in Chromium)
    docker exec oidf-runner-1 sh /laravel-oidc/conformance/run-rp-plan.sh rp-logout \
      "oidcc-client-rp-initiated-logout-rp-basic[client_auth_type=client_secret_basic][client_registration=static_client][request_type=plain_http_request]" 1
    ```

    Back-channel and front-channel use the aliases `rp-backchannel` / `rp-frontchannel` and the plans `oidcc-client-back-channel-logout-rp-basic` / `oidcc-client-front-channel-logout-rp-basic` with the same variants and `1`.

5. **Key rotation** (on the Config RP plan id printed in `runner-rp-config.log`): start `rp-driver.py` in the runner with `RP_SECOND_LOGIN=1` and run `python /laravel-oidc/conformance/run-key-rotation.py <plan-id> oidcc-client-test-signing-key-rotation`, then run `-just-before-signing` with a driver started without `RP_SECOND_LOGIN`.

Results: one zip per plan in `RESULTS_DIR`, plus `rp-evidence.log` and the runner logs. The RP's reasons are in `rp-app/storage/logs/laravel.log`. Run one plan at a time, and only one driver: two drivers sign in twice per module, and the suite then refuses the second code.

## CI job proposal

A scheduled workflow on a standard `ubuntu-latest` runner, which is free for this public repository. It needs Docker only (already on the runner), takes about 15 minutes, and is **not** a required check. A suite update or the `latest` browser image can break it without any change here. Outline:

```yaml
name: openid-conformance
on:
    schedule:
        - cron: '41 3 * * 1' # weekly; nightly is fine too
    workflow_dispatch:
permissions:
    contents: read
jobs:
    rp-conformance:
        runs-on: ubuntu-latest
        timeout-minutes: 45
        env:
            CONFORMANCE_SUITE_REF: release-v5.1.43
        steps:
            - uses: actions/checkout@<sha> # pin by SHA, path: laravel-oidc
            - uses: shivammathur/setup-php@<sha> # PHP 8.4 + composer, to create the harness app
            - run: git clone --depth 1 --branch "$CONFORMANCE_SUITE_REF" https://gitlab.com/openid/conformance-suite.git suite
            - run: docker run --rm -v "$PWD/suite":/src -w /src maven:3-eclipse-temurin-21 mvn -B -q -DskipTests package
            - run: ./laravel-oidc/conformance/ci-prepare-harness.sh # step 2 above, scripted
            - run: | # step 3, then step 4 for each plan, restarting rp per alias
                  docker compose -p oidf -f suite/docker-compose-localtest.yml -f laravel-oidc/conformance/docker-compose.rp.yml up -d …
            - run: python3 suite/…/check-results.py results # fail on FAILED / WARNING / INTERRUPTED, not on REVIEW or SKIPPED
            - uses: actions/upload-artifact@<sha> # results/, rp-evidence.log, laravel.log
              if: always()
```

The follow-up PR would add the workflow in its own commit, the small `ci-prepare-harness.sh`, and a results check like Signaculum's `conformance/check-results.py`. A red scheduled run should open or update a `[conformance]` issue instead of blocking merges.

## Formal certification (not started)

Nothing has been registered or paid. What it would take:

- **Profiles**: Basic RP, Config RP, RP-Initiated Logout RP, Back-Channel Logout RP and Front-Channel Logout RP.
- **Run on the hosted suite** (`https://www.certification.openid.net/`) and use **Publish for certification** on each plan. Whether exports from a self-hosted suite are accepted is not documented; ask `certification@oidf.org` first. For RP certification, each test also needs **RP evidence** uploaded with the export: log excerpts or screenshots, one or more files per test, named with the test name as a prefix, showing that the RP detected the error. `rp-evidence.log` and the Laravel log hold that evidence, but they have to be split per test. The harness would need a publicly reachable HTTPS deployment for the hosted suite (a dedicated test app, never a product's production).
- **Fee** (OpenID Foundation fee schedule, read 2026-11-27): USD 3,500 per deployment for non-members and USD 700 for members, covering every OpenID Connect profile of that deployment within a calendar year. **RP and OP are separate payments**, so Signaculum (OP) and this package (RP) would be two certifications.
- **Open-source waiver**: one fee waiver per project per year, covering OP and/or RP. Conditions: the requester is an OpenID Foundation member in good standing, none of the primary maintainers are paid for their work on the project, and all relevant profiles of the specification are submitted at once. Further requests within the year cost USD 100, and each request is decided case by case.
- **Submission**: the zips with evidence, a payment code (or waiver), the form at `submissions.openid.net`, and a Declaration of Conformance signed through DocuSign by the maintainer. Certifications do not expire.

Sources: <https://openid.net/certification/>, <https://openid.net/certification/fees/>, <https://openid.net/how-to-submit-your-certification-request/>, <https://openid.net/certification/open-source-project-certification-policy/>, <https://openid.net/certification/what-is-self-certification-faq/>.
