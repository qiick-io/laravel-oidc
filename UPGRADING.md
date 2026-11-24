# Upgrading


## Post-logout return route (from 1.0.0-beta.6)

RP-initiated logout now sends a `state` and, by default, asks the IdP to return to the package route `{APP_URL}/auth/oidc/logged-out`, which checks that state and then redirects to `oidc.logout.redirect_to` (default `/`).

- **Register `{APP_URL}/auth/oidc/logged-out` at the IdP** as a post-logout redirect URI (`php artisan oidc:configure` prints it). Until it is registered, the IdP refuses to redirect there after logout.
- Set `oidc.logout.redirect_to` to the page users should land on (for example `/login`).
- An app that sets `oidc.post_logout_redirect_uri`, or passes `postLogoutRedirectUri` from its own `ProviderConfigurationRepositoryContract`, keeps its URI and skips the state check; pass `route('oidc.logged-out')` there to get it.
- An app that owns its routes can leave the route out with `oidc.routes.except = ['oidc.logged-out']`; the default post-logout URI then falls back to `{APP_URL}/`.

## Adopting `qiick/laravel-outbound` (from 1.0.0-beta.4)

### Composer

```bash
composer require qiick/laravel-oidc:^1.0@beta
# pulls qiick/laravel-outbound:^0.1 transitively
```

No separate outbound publish is required for OIDC. Keep using the OIDC config keys below.

### Config (public keys unchanged unless noted)

| Key / env | Effect |
| --- | --- |
| `oidc.http.allow_private_hosts` / `OIDC_ALLOW_PRIVATE_HOSTS` | When `true`, private / loopback / link-local hosts and plain `http` are allowed together (lab / Docker IdPs). Cloud metadata stays blocked. Mapped onto outbound `UrlGuardOptions`. |
| `oidc.http.timeout` / `OIDC_HTTP_TIMEOUT` | Per-hop timeout for IdP calls (seconds, default `10`). **`0` still means no practical limit** (mapped to a 24h ceiling for outbound's ≥1s contract). |
| `oidc.http.connect_timeout` / `OIDC_HTTP_CONNECT_TIMEOUT` | **New (optional).** TCP connect timeout (seconds, default `10`, same as before). `0` means no practical limit. |
| `oidc.http.max_response_bytes` / `OIDC_MAX_RESPONSE_BYTES` | **New.** Cap on IdP response bodies (default `1048576`). |

Do not rely on `OUTBOUND_ALLOW_PRIVATE_HOSTS` for this package: OIDC builds its own guard / pinned client privately and maps `oidc.http.allow_private_hosts` onto the options it passes. Installing both packages does not let outbound's SSRF or timeout ceilings override IdP calls.

### Removed

- `Qiick\Oidc\Services\RemoteUrlGuardService` — construct outbound's `Qiick\Outbound\Ssrf\RemoteUrlGuard` in tests if needed. `FakeIdentityProvider::fake()` only rebinds OIDC's private host resolver (`OidcOutboundStackFactory::HostResolverBinding` / `oidc.ssrf.host_resolver`), never the shared outbound singletons.

### Behaviour

IdP HTTP still refuses redirects, still pins with `CURLOPT_CONNECT_TO`, and still fails closed on SSRF. Outbound additionally enforces response size limits on every IdP call.

**NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`) and Teredo (`2001::/32`) are now always blocked**, including when `OIDC_ALLOW_PRIVATE_HOSTS=true`. Previously those transition prefixes could be reached under the private-host opt-in; outbound's guard refuses them unconditionally so an IdP URL or DNS answer cannot tunnel to metadata or loopback through them.
