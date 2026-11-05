@php
/** @var \Laravel\Boost\Install\GuidelineAssist $assist */
@endphp
# qiick/laravel-oidc

OpenID Connect single sign-on for this app. It works with any standard IdP (Keycloak, Zitadel, Authentik, Entra ID, Google, Signaculum). SSO is optional: local login keeps working unless SSO-only mode is on.

## Set it up end to end

1. `php artisan migrate` (creates `user_identities`).
2. `php artisan oidc:configure --issuer=... --client-id=... --client-secret=... --json`. It checks discovery, PKCE support, the JWKS, the signing algorithms and the redirect URI, and lists the URIs to register at the IdP (`register_at_identity_provider`). Exit code 0 means no failure.
3. Register the printed `redirect_uri`, `post_logout_redirect_uri` and `backchannel_logout_uri` at the IdP.
4. Rerun with `--write-env` to write `OIDC_ENABLED`, `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` to `.env`. Never commit `.env` or a client secret.
5. Point the login page's SSO button at `route('oidc.redirect')`. Get the button label and visibility from `app(\Qiick\Oidc\Services\SsoOnlyModeService::class)->loginOptions($request)->toArray()`.

## Rules

- The identity key is (`issuer`, `sub`) in `user_identities`. Never match users by email yourself; `OIDC_AUTO_LINK` does it safely for a trusted IdP only.
- Never weaken validation: no `alg` other than asymmetric ones, no skipping `state`, `nonce`, PKCE or the SSRF guard, no `OIDC_ALLOW_PRIVATE_HOSTS` outside local QA.
- Role mapping (`oidc.roles`) only grants app roles listed as values of `oidc.roles.map`; `super-admin` is never granted. Do not try to map it.
- In SSO-only mode (`OIDC_ONLY`) call `SsoOnlyModeService::canUseLocalLogin($user)` in custom login callbacks (`Fortify::authenticateUsing()`, `Passkeys::authorizeLoginUsing()`). Keep at least one break-glass account (`oidc.break_glass.roles` with a confirmed second factor); `oidc:configure` fails without one.
- Before ending a session yourself, read `RpInitiatedLogoutService::endSessionUrl($request->session())` and redirect there after `Auth::logout()`.
- Settings in a database: bind `ProviderConfigurationRepositoryContract`. JIT users with custom columns: bind `UserProvisioningContract`. 2FA policy: bind `SecondFactorChallengeContract`.

## Tests

Use `Qiick\Oidc\Testing\FakeIdentityProvider::fake()`; never call a real IdP in tests:

```php
$identityProvider = FakeIdentityProvider::fake();
$authorizationUrl = $this->get(route('oidc.redirect'))->headers->get('Location');
$this->get($identityProvider->authorize($authorizationUrl, ['sub' => 'user-1', 'email' => 'ada@example.com']));
```
