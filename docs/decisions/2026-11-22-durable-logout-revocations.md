# 2026-11-22: Keep logout revocations durable

The maintainer chose the `oidc_logout_revocations` table as the source of truth for accepted logout notices. The cache accelerates lookups. Each cache miss falls through to the table, and a failed read ends the OIDC session. This lets the relying party honour accepted logouts after eviction, a cache flush or a request reaching another app server.

The package also supports front-channel logout as an opt-in for providers that require browser notices. The signed back-channel path serves installations that support it. The package uses Laravel sessions and defers a separate durable `oidc_sessions` table until a product needs it.
