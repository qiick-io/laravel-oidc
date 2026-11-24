#!/usr/bin/env bash
# Per-class mutation gate: every listed class must reach pest --mutate --min
# (default 95) on its own. One pest --mutate invocation per class (pcov).
# Never --covered-only, never || true, and no @pest-mutate-ignore in src/.
#
# CI splits the list into parallel shards: MUTATE_SHARD=i MUTATE_SHARDS=n runs
# the classes at positions i, i+n, i+2n, ... (1-based). Without them, every
# class runs, as locally.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

min="${MUTATE_MIN:-95}"
shard="${MUTATE_SHARD:-1}"
shards="${MUTATE_SHARDS:-1}"
# Default scope: the feature suite (the integration groups need live IdPs).
paths="${MUTATE_PATHS:-tests/Feature}"

classes=(
  'Qiick\Oidc\Console\ConfigureOidcCommand'
  'Qiick\Oidc\Data\LoginOptionsData'
  'Qiick\Oidc\Factories\OidcOutboundStackFactory'
  'Qiick\Oidc\Http\Controllers\PostLogoutReturnController'
  'Qiick\Oidc\Listeners\EnforceSsoOnlyListener'
  'Qiick\Oidc\Listeners\PromotePendingIdentityListener'
  'Qiick\Oidc\Services\DiscoveryService'
  'Qiick\Oidc\Services\IdTokenValidatorService'
  'Qiick\Oidc\Services\IdentityProviderHttpService'
  'Qiick\Oidc\Services\JwksService'
  'Qiick\Oidc\Services\JwtValidatorService'
  'Qiick\Oidc\Services\RpInitiatedLogoutService'
  'Qiick\Oidc\Services\SessionRevocationService'
  'Qiick\Oidc\Services\SsoOnlyModeService'
  'Qiick\Oidc\Services\UserinfoService'
)

status=0

for index in "${!classes[@]}"; do
  if (( index % shards != shard - 1 )); then
    continue
  fi

  class="${classes[$index]}"
  echo "==> mutate ${class} (min=${min}, shard ${shard}/${shards})"
  # shellcheck disable=SC2086
  if ! vendor/bin/pest --mutate --class="${class}" --min="${min}" ${paths} "$@"; then
    status=1
  fi
done

exit "${status}"
