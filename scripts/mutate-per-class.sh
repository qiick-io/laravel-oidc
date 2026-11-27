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

# A shard outside 1..shards would run no class and pass: refuse it.
if ! [[ "${shards}" =~ ^[1-9][0-9]*$ && "${shard}" =~ ^[1-9][0-9]*$ ]] || (( shard > shards )); then
  echo "MUTATE_SHARD=${shard} is not within 1..MUTATE_SHARDS=${shards}" >&2
  exit 2
fi

classes=(
  'Qiick\Oidc\Console\ConfigureOidcCommand'
  'Qiick\Oidc\Console\ImportLegacySubjectsCommand'
  'Qiick\Oidc\Console\PruneLogoutRevocationsCommand'
  'Qiick\Oidc\Data\AuthenticatedIdentityData'
  'Qiick\Oidc\Data\DiscoveryDocumentData'
  'Qiick\Oidc\Data\IdentitySessionData'
  'Qiick\Oidc\Data\LoginOptionsData'
  'Qiick\Oidc\Data\PersonNameData'
  'Qiick\Oidc\Data\ProviderConfigurationData'
  'Qiick\Oidc\Exceptions\LoginRefusedException'
  'Qiick\Oidc\Factories\OidcOutboundStackFactory'
  'Qiick\Oidc\Http\Controllers\BackChannelLogoutController'
  'Qiick\Oidc\Http\Controllers\FrontChannelLogoutController'
  'Qiick\Oidc\Http\Controllers\OidcCallbackController'
  'Qiick\Oidc\Http\Controllers\OidcRedirectController'
  'Qiick\Oidc\Http\Controllers\PostLogoutReturnController'
  'Qiick\Oidc\Http\Middleware\EnsureOidcSessionIsActiveMiddleware'
  'Qiick\Oidc\Laravel\OidcServiceProvider'
  'Qiick\Oidc\Listeners\EnforceSsoOnlyListener'
  'Qiick\Oidc\Listeners\PromotePendingIdentityListener'
  'Qiick\Oidc\Models\Concerns\GuardsIdByDefaultTrait'
  'Qiick\Oidc\Models\OidcLogoutRevocation'
  'Qiick\Oidc\Models\UserIdentity'
  'Qiick\Oidc\Repositories\ConfigProviderConfigurationRepository'
  'Qiick\Oidc\Services\AuthorizationCodeFlowService'
  'Qiick\Oidc\Services\BackChannelLogoutService'
  'Qiick\Oidc\Services\Concerns\ChecksTwoFactorSecretTrait'
  'Qiick\Oidc\Services\DiscoveryService'
  'Qiick\Oidc\Services\EloquentUserProvisioningService'
  'Qiick\Oidc\Services\FortifySecondFactorChallengeService'
  'Qiick\Oidc\Services\IdTokenValidatorService'
  'Qiick\Oidc\Services\IdentityProviderHttpService'
  'Qiick\Oidc\Services\IdentitySessionService'
  'Qiick\Oidc\Services\JwksService'
  'Qiick\Oidc\Services\JwtValidatorService'
  'Qiick\Oidc\Services\MultiFactorClaimService'
  'Qiick\Oidc\Services\OidcLoginService'
  'Qiick\Oidc\Services\RoleBreakGlassPolicyService'
  'Qiick\Oidc\Services\RoleMappingService'
  'Qiick\Oidc\Services\RpInitiatedLogoutService'
  'Qiick\Oidc\Services\SessionRevocationService'
  'Qiick\Oidc\Services\SpatieRoleSynchronizationService'
  'Qiick\Oidc\Services\SsoOnlyModeService'
  'Qiick\Oidc\Services\UserLinkingService'
  'Qiick\Oidc\Services\UserinfoService'
  'Qiick\Oidc\Testing\FakeIdentityProvider'
  'Qiick\Oidc\Enums\LoginRefusalReasonEnum'
  'Qiick\Oidc\Erasure\ErasureReport'
  'Qiick\Oidc\Erasure\OidcEraser'
  'Qiick\Oidc\Console\CheckOidcCommand'
)

status=0

for index in "${!classes[@]}"; do
  if (( index % shards != shard - 1 )); then
    continue
  fi

  class="${classes[$index]}"
  class_paths="$paths"
  class_options=(--mutate --class="${class}" --min="${min}")
  if [[ -z "${MUTATE_PATHS:-}" && "$class" == Qiick\\Oidc\\Erasure\\* ]]; then
    class_paths="tests/Feature/OidcEraserTest.php tests/Erasure"
  fi
  if [[ "$class" == 'Qiick\Oidc\Enums\LoginRefusalReasonEnum' ]]; then
    # Pest currently produces zero mutants for the enum's literal match arms.
    # The feature suite checks every case, and any future mutants still need 95%.
    class_options+=(--ignore-min-score-on-zero-mutations)
  fi
  echo "==> mutate ${class} (min=${min}, shard ${shard}/${shards})"
  # shellcheck disable=SC2086
  if ! vendor/bin/pest "${class_options[@]}" ${class_paths} "$@"; then
    status=1
  fi
done

exit "${status}"
