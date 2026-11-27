# 2026-11-22: Defer token storage and refresh

The maintainer accepted the standards review decision to defer a token vault, `offline_access` and refresh-token rotation until a product needs them. The authorization-code flow uses access tokens for the immediate userinfo request and keeps the encrypted ID token in the Laravel session for logout.

A future vault can ship in an additive migration. Designing an empty token table before the first consumer would commit the schema without the refresh, revocation and retention requirements that determine its shape.
