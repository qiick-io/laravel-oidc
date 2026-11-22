# Upgrading

## Adopting `qiick/laravel-outbound` (from 1.0.0-beta.4)

### Composer

```bash
composer require qiick/laravel-oidc:^1.0@beta
# pulls qiick/laravel-outbound:^0.1 transitively
```

No separate outbound publish is required for OIDC. Keep using the OIDC config keys below.

### Config (public keys unchanged)

| Key / env | Effect |
| --- | --- |
| `oidc.http.allow_private_hosts` / `OIDC_ALLOW_PRIVATE_HOSTS` | When `true`, private / loopback / link-local hosts and plain `http` are allowed together (lab / Docker IdPs). Cloud metadata stays blocked. Mapped onto outbound `UrlGuardOptions`. |
| `oidc.http.timeout` / (default `10`) | Per-hop timeout for IdP calls (seconds). |
| `oidc.http.max_response_bytes` / `OIDC_MAX_RESPONSE_BYTES` | **New.** Cap on IdP response bodies (default `1048576`). |

Do not rely on `OUTBOUND_ALLOW_PRIVATE_HOSTS` for this package: OIDC maps its own key onto the guard options it passes to outbound.

### Removed

- `Qiick\Oidc\Services\RemoteUrlGuardService` — use outbound's `Qiick\Outbound\Ssrf\RemoteUrlGuard` (or the container binding) if an app was constructing the old class in tests. `FakeIdentityProvider::fake()` still swaps the resolver for you.

### Behaviour

IdP HTTP still refuses redirects, still pins with `CURLOPT_CONNECT_TO`, and still fails closed on SSRF. Outbound additionally enforces response size limits on every IdP call.
