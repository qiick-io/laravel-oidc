# 2026-11-22: Defer the multi-provider registry

The maintainer accepted the 1.0 standards review. The package supports one configured OpenID Provider at a time. Identity matching stays keyed by the exact `(issuer, subject)` pair.

The `user_identities.subject_type` and `user_identities.provider_key` columns are reserved for the multi-provider registry (L4). Package login and import leave both `NULL` until that work defines how to populate them. This preserves space for provider and subject metadata before the first stable migration freeze.
