# Migrating Externa and Excubia App to `qiick/laravel-oidc`

Both apps carry a copy of the same Socialite OIDC client (Excubia App's says "Copied from qiick-io/externa-core until Signaculum SSO exists"). This guide replaces both copies with the package. The migration happens after Externa 1.4.0 and the Excubia beta ship (design decision of 2026-11-05).

The steps are the same for both apps. The app-specific parts are marked **Externa** or **Excubia App**.

## 1. What changes for users and admins

Read this first. The first four points are deliberate behaviour changes from the accepted design, and the release notes must say so.

| Today | With the package | Why |
| --- | --- | --- |
| A matching verified email always links an unknown SSO identity to the local user. | Only with auto-link on (`OIDC_AUTO_LINK`, **off by default**, Decision Luca 2026-11-13). | An IdP that lets users choose their email could take over accounts. Existing SSO installs that still need email linking must turn auto-link on (or run `oidc:import-legacy-subjects`; see step 4). |
| An SSO login skips the app's 2FA, even with `two_factor_required`. | With `two_factor_required`, an SSO login counts only if the `id_token` shows MFA (`amr` in `oidc.mfa.amr_values` or `acr` in `oidc.mfa.acr_values`); otherwise the app's TOTP challenge runs. | Closes the documented gap. Release notes: SSO does not skip the app's 2FA. |
| SSO logins set the remember-me cookie (Externa: `Auth::login($user, remember: true)`). | No remember-me cookie (`oidc.remember` is off). | A remember cookie would outlive the IdP session and a back-channel logout. |
| Identity data comes from userinfo only, without `id_token` validation, PKCE or `nonce`. | Authorization code flow with PKCE `S256`, `state` and `nonce`; the `id_token` is validated; userinfo is added on top. | Protocol profile, design section 3. |
| Logout ends the local session only. | RP-initiated logout also ends the IdP session; back-channel logout from the IdP ends local sessions. | Design section 3, "Logout". |
| Route names `auth.oidc.redirect` / `auth.oidc.callback`. | `oidc.redirect` / `oidc.callback`, with the same paths (`/auth/oidc/redirect`, `/auth/oidc/callback`). | The redirect URI registered at the IdP does not change. |

New and optional: SSO-only mode with a break-glass admin, role mapping, `oidc:configure`.

## 2. Install

```bash
composer require qiick/laravel-oidc
php artisan migrate                    # user_identities
php artisan oidc:import-legacy-subjects
```

`oidc:import-legacy-subjects` copies every `users.oidc_sub` into `user_identities` with the issuer of the configured SSO provider. Users then keep signing in with the same IdP account. It is idempotent, `--dry-run` reports without writing (also before `migrate`), and a `sub` already linked to another user is reported (exit code 1), never moved. Keep `users.oidc_sub` for one release, then drop it in a new forward-only migration. Never edit the old one.

Run the import from a migration or a deploy step, after the issuer setting is known. The command takes the issuer from the bound `ProviderConfigurationRepositoryContract` (the repository binding of step 3 in an app with database settings), never from `oidc.issuer` directly. While SSO is not configured yet (the repository's `isEnabled()` is false), pass `--issuer` explicitly; the command refuses to guess.

## 3. Read the settings from the database

Both apps keep the `oidc_*` settings in their settings table, edited in the admin UI. Keep the keys and the UI. Bind a repository that reads them, and fall back to the env vars for empty values:

```php
// app/Services/Auth/OidcSettingsRepositoryService.php (Externa) or app/Services/OidcSettingsRepositoryService.php (Excubia App)
final readonly class OidcSettingsRepositoryService implements ProviderConfigurationRepositoryContract
{
    public function __construct(
        private ProjectSettingsService $settings,                 // Excubia App: SettingsRepositoryService
        private ConfigProviderConfigurationRepository $fromConfig,
    ) {}

    public function isEnabled(): bool
    {
        return $this->settings->isOidcLoginAvailable() || $this->fromConfig->isEnabled();
    }

    public function configuration(): ProviderConfigurationData
    {
        if (! $this->settings->isOidcLoginAvailable()) {
            return $this->fromConfig->configuration();
        }

        return new ProviderConfigurationData(
            issuer: rtrim((string) $this->settings->oidcIssuer(), '/'),
            clientId: (string) $this->settings->oidcClientId(),
            clientSecret: $this->settings->oidcClientSecret(),       // already decrypted by the service
            redirectUri: url('auth/oidc/callback'),
            scopes: ['openid', 'profile', 'email'],
            postLogoutRedirectUri: route('oidc.logged-out'), // checks the logout state; set oidc.logout.redirect_to to '/login'
        );
    }
}

// AppServiceProvider::register()
$this->app->bind(ProviderConfigurationRepositoryContract::class, OidcSettingsRepositoryService::class);
```

- **Issuer:** today both apps `rtrim('/')` the issuer before discovery. The package compares the issuer with the discovery document exactly. Keep the `rtrim` only if the IdP publishes its issuer without a trailing slash (Keycloak, Zitadel, Signaculum). Entra ID and Google publish none either. `oidc:configure` says which one is right.
- **Other settings** come from config, set in `config/oidc.php` or at runtime in the same provider:
  - `jit` ← `oidc_jit_provisioning`;
  - `allowed_domains` ← **Externa** `allowedDomains()`;
  - `auto_link`: see step 4;
  - `users.active_column` = `is_active` (both apps).
- **Docker settings:** `config/services.php` `oidc.discovery_base`, `server_origin` and `allow_private_hosts` move to `oidc.http.*`. The env var names stay the same (`OIDC_DISCOVERY_BASE`, `OIDC_SERVER_ORIGIN`, `OIDC_ALLOW_PRIVATE_HOSTS`), so `compose.oidc.yaml` keeps working.

## 4. Linking and JIT

- **Auto-link.** Package default `oidc.auto_link` / `OIDC_AUTO_LINK` is **`false`** (Decision Luca, 2026-11-13): opt in per provider for a trusted IdP. Today Externa/Excubia always auto-link by email; after migration keep logins working for users who have never signed in through SSO only by turning auto-link on (or by running `oidc:import-legacy-subjects` so identities already exist). Show the switch next to JIT with the warning from the README.
- **Provisioning.** Bind `UserProvisioningContract` with the user creation each app does today. Take the names from `$identity->personName()`: it returns `given_name` → `first_name` and `family_name` → `last_name`, the rule agreed with Signaculum (its `profile` scope sends both). For IdPs without `given_name` it splits `name`, with the **last** word as the last name.
  - **Externa:** first and last name from `personName()`, `password = null`, `email_verified_at = now()`, `is_active = true`, then `default_user_role()` if it exists and `is_assignable`;
  - **Excubia App:** the same fields, plus the `reader` role (`RoleEnum::Reader`).

  Behaviour change: today both apps take the **first** word of `name` as the first name and the rest as the last name, and copy the first name into the last name for a one-word name. With the package, "Maria Luisa Rossi" becomes `Maria Luisa` / `Rossi` instead of `Maria` / `Luisa Rossi`, and a one-word name gets an empty last name. If the `last_name` column is not nullable, store `''` or keep the old copy for that case. The package does not update names on later logins. To refresh them, listen to `OidcLoginSucceededEvent`.
- **Messages.** The refusal messages keep Externa's English wording (`LoginRefusalReasonEnum::message()`), so existing translations still match.

## 5. 2FA

Bind `SecondFactorChallengeContract` to the app's setting. The default service already starts Fortify's challenge, so only `isRequired()` changes:

```php
final readonly class SsoSecondFactorChallengeService implements SecondFactorChallengeContract
{
    public function __construct(private ProjectSettingsService $settings) {}   // Excubia App: SettingsRepositoryService

    public function isRequired(Model&Authenticatable $user): bool
    {
        return $this->settings->isTwoFactorRequired();
    }

    public function challenge(Request $request, Model&Authenticatable $user, bool $shouldRemember): ?Response
    {
        return (new FortifySecondFactorChallengeService(isRequiredByDefault: true))->challenge($request, $user, $shouldRemember);
    }
}
```

**Excubia App** has `EnsureTwoFactorIsEnabled`, which sends users without 2FA to set it up. It keeps working after an SSO login, as after a password login.

## 6. SSO-only mode (optional)

Both apps check `is_active` in `Fortify::authenticateUsing()` (**Excubia App**) and `Passkeys::authorizeLoginUsing()`. Add the package check there, or SSO-only mode cannot stop those logins:

```php
&& app(SsoOnlyModeService::class)->canUseLocalLogin($user)
```

Break-glass accounts are `super-admin` users with confirmed 2FA (both apps have the Spatie role `super-admin`). Add an `oidc_only` setting next to the other SSO settings if the UI should control it.

## 7. Login page

Replace `canUseOidc` / `oidcButtonLabel` (shared in `FortifyServiceProvider::loginView`) with the package's options:

```php
'oidc' => app(SsoOnlyModeService::class)->loginOptions($request)->toArray(),
// isSsoAvailable, isSsoOnly, isPasswordLoginVisible, buttonLabel, redirectUrl
```

In `resources/js/pages/auth/login.tsx`, regenerate Wayfinder and import `redirect` from `@/routes/oidc` instead of `@/routes/auth/oidc`, or use `oidc.redirectUrl`. Hide the password form when `isPasswordLoginVisible` is false.

## 8. Logout

In the app's logout (Fortify `LogoutResponse` or the logout controller), read the IdP logout URL before the session is invalidated, then redirect there:

```php
$endSessionUrl = app(RpInitiatedLogoutService::class)->endSessionUrl($request->session());
// ... Auth::logout(), invalidate, regenerateToken ...
return $endSessionUrl !== null ? redirect()->away($endSessionUrl) : redirect('/');
```

Register at the IdP the URIs that `php artisan oidc:configure` prints:
- the post-logout redirect URI;
- the back-channel logout URI `{APP_URL}/auth/oidc/backchannel-logout`.

The back-channel logout needs a cache store shared by all app servers (database or Redis, not `array` or a per-server `file`).

## 9. Activity log

Both apps log logins and settings changes. Listen to `OidcLoginSucceededEvent`, `OidcIdentityLinkedEvent` and `OidcUserProvisionedEvent` for the SSO entries that `OidcController` writes today, if any.

## 10. Delete the copies

**Externa** (`externa-core`):
- `app/Auth/Oidc/GenericOidcProvider.php`
- `app/Http/Controllers/Auth/OidcController.php`
- `app/Services/Auth/OidcSocialiteFactoryService.php`
- `app/Services/Auth/OidcUserResolverService.php`
- the `auth/oidc/*` routes in `routes/web.php`
- `tests/Support/FakeOidcSocialiteFactory.php`
- `laravel/socialite`, if nothing else uses it
- the `services.oidc` block

**Excubia App** (`excubia-app`):
- `app/Auth/Oidc/GenericOidcProvider.php`
- `app/Http/Controllers/Auth/OidcController.php`
- `app/Services/OidcSocialiteFactoryService.php`
- `app/Services/OidcUserResolverService.php`
- its compact SSRF guard
- the `auth/oidc/*` routes
- `laravel/socialite`, if unused

## 11. Tests

Replace the Socialite fakes with the package's IdP:

```php
$identityProvider = FakeIdentityProvider::fake(); // set your settings rows to its issuer, client id and secret if the app reads the database
$authorizationUrl = $this->get(route('oidc.redirect'))->headers->get('Location');
$this->get($identityProvider->authorize($authorizationUrl, ['sub' => 'sub-abc', 'email' => 'sso@example.com']))->assertRedirect();
```

Port each case of `OidcAuthenticationTest`:
- sub match, email link, link to another sub, inactive user;
- JIT on and off, allowed domains, unverified email;
- the button visibility.

Add tests for:
- the 2FA challenge with and without `amr: ["mfa"]`;
- SSO-only mode with a break-glass account;
- the RP logout redirect.

## 12. Keycloak QA

**Externa's** `compose.oidc.yaml` keeps working. Add three attributes to `docker/keycloak/realm-externa.json`:
- `"pkce.code.challenge.method": "S256"`;
- `"post.logout.redirect.uris"`;
- `"backchannel.logout.url"`.

`tests/Fixtures/Keycloak/realm-laravel-oidc.json` in this repo is a working example.

## Checklist

- [ ] `composer require qiick/laravel-oidc`, `migrate`, `oidc:import-legacy-subjects`
- [ ] `ProviderConfigurationRepositoryContract` reads the `oidc_*` settings
- [ ] `oidc.users.active_column = is_active`, `jit`, `allowed_domains`
- [ ] Auto-link default applied (`OIDC_AUTO_LINK=false`; opt in only for a trusted IdP)
- [ ] `UserProvisioningContract` (names, password `null`, default role)
- [ ] `SecondFactorChallengeContract` reads `two_factor_required`
- [ ] `canUseLocalLogin()` in `authenticateUsing` / `authorizeLoginUsing`
- [ ] Login page props and Wayfinder import
- [ ] Logout redirects to `endSessionUrl()`; URIs registered at the IdP
- [ ] Shared cache store for back-channel logout
- [ ] Copies, routes and Socialite removed; tests ported
- [ ] Release notes list the behaviour changes of section 1
