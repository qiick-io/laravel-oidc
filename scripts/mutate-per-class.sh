#!/usr/bin/env bash
# Run pest mutation per security class so each stays >= MUTATE_MIN (default 95).
# Usage: scripts/mutate-per-class.sh [extra pest args...]
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

min="${MUTATE_MIN:-95}"
# No --covered-only: every mutated line in the listed classes must be killed.
paths="${MUTATE_PATHS:-tests/Feature}"

classes=(
  'Qiick\Oidc\Services\IdentityProviderHttpService'
)

status=0

for class in "${classes[@]}"; do
  echo "==> mutate ${class} (min=${min})"
  # shellcheck disable=SC2086
  if ! vendor/bin/pest --mutate --class="${class}" --min="${min}" ${paths} "$@"; then
    status=1
  fi
done

exit "${status}"
