#!/usr/bin/env bash
# Prepare a throwaway Zitadel IdP for `pest --group=zitadel`.
# Pins ghcr.io/zitadel/zitadel:v4.16.0 + postgres:17.10-alpine (official compose tags).
# Uses Login V1 (LOGINV2_REQUIRED=false) so the suite can drive the HTML forms with Guzzle.
# Does not touch Herd, laravel-oidc-keycloak, or unrelated Docker resources.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

ZITADEL_IMAGE="${ZITADEL_IMAGE:-ghcr.io/zitadel/zitadel:v4.16.0}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:17.10-alpine}"
# Default 8085: Luca's Mac often has another PHP listener on IPv4 :8080; Docker
# then only wins on IPv6 and CURLOPT_RESOLVE to 127.0.0.1 hits the wrong process.
ZITADEL_PORT="${ZITADEL_PORT:-8085}"
ZITADEL_URL="${ZITADEL_URL:-http://localhost:${ZITADEL_PORT}}"
ZITADEL_MASTERKEY="${ZITADEL_MASTERKEY:-MasterkeyNeedsToHave32Characters}"
NETWORK_NAME="${ZITADEL_NETWORK_NAME:-laravel-oidc-zitadel}"
DB_CONTAINER="${ZITADEL_DB_CONTAINER:-laravel-oidc-zitadel-db}"
ZITADEL_CONTAINER="${ZITADEL_CONTAINER:-laravel-oidc-zitadel}"
RUN_STATE_DIR="${ZITADEL_RUN_STATE_DIR:-${TMPDIR:-/tmp}/laravel-oidc-zitadel-run}"
BOOTSTRAP_DIR="${RUN_STATE_DIR}/bootstrap"
CREDENTIALS_PATH="${ZITADEL_CREDENTIALS:-${RUN_STATE_DIR}/credentials.json}"
PAT_PATH="${BOOTSTRAP_DIR}/admin.pat"

mkdir -p "${BOOTSTRAP_DIR}"
chmod 777 "${BOOTSTRAP_DIR}"
rm -f "${CREDENTIALS_PATH}" "${PAT_PATH}" "${RUN_STATE_DIR}/env.sh"

# Only remove the containers / network this script owns.
docker rm -f "${ZITADEL_CONTAINER}" "${DB_CONTAINER}" >/dev/null 2>&1 || true
docker network rm "${NETWORK_NAME}" >/dev/null 2>&1 || true
docker network create "${NETWORK_NAME}" >/dev/null

docker run -d --name "${DB_CONTAINER}" \
  --network "${NETWORK_NAME}" \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=zitadel \
  "${POSTGRES_IMAGE}" >/dev/null

for attempt in $(seq 1 60); do
  if docker exec "${DB_CONTAINER}" pg_isready -d zitadel -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Host must be "localhost" (not 127.0.0.1): Zitadel resolves the instance by Host.
docker run -d --name "${ZITADEL_CONTAINER}" \
  --network "${NETWORK_NAME}" \
  -p "${ZITADEL_PORT}:8080" \
  -v "${BOOTSTRAP_DIR}:/zitadel/bootstrap" \
  -e ZITADEL_EXTERNALDOMAIN=localhost \
  -e ZITADEL_EXTERNALPORT="${ZITADEL_PORT}" \
  -e ZITADEL_EXTERNALSECURE=false \
  -e ZITADEL_TLS_ENABLED=false \
  -e "ZITADEL_DATABASE_POSTGRES_DSN=postgresql://postgres:postgres@${DB_CONTAINER}:5432/zitadel?sslmode=disable" \
  -e ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORDCHANGEREQUIRED=false \
  -e ZITADEL_FIRSTINSTANCE_PATPATH=/zitadel/bootstrap/admin.pat \
  -e ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_USERNAME=zitadel-admin-sa \
  -e ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_NAME=Admin \
  -e ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_EXPIRATIONDATE=2099-01-01T00:00:00Z \
  -e ZITADEL_DEFAULTINSTANCE_FEATURES_LOGINV2_REQUIRED=false \
  "${ZITADEL_IMAGE}" \
  start-from-init --masterkey "${ZITADEL_MASTERKEY}" --tlsMode disabled >/dev/null

echo "Waiting for Zitadel at ${ZITADEL_URL} …"
for attempt in $(seq 1 90); do
  if [[ -f "${PAT_PATH}" ]] \
    && curl -sf "${ZITADEL_URL}/.well-known/openid-configuration" >/dev/null \
    && curl -sf -H "Authorization: Bearer $(cat "${PAT_PATH}")" "${ZITADEL_URL}/management/v1/orgs/me" >/dev/null; then
    break
  fi

  if [[ "${attempt}" -eq 90 ]]; then
    echo "Zitadel did not become ready" >&2
    docker logs "${ZITADEL_CONTAINER}" >&2 || true
    exit 1
  fi

  sleep 2
done

# Management can still flap briefly after the first successful call.
seed_ok=0
for attempt in $(seq 1 10); do
  if ZITADEL_URL="${ZITADEL_URL}" \
    ZITADEL_PAT_PATH="${PAT_PATH}" \
    ZITADEL_CREDENTIALS="${CREDENTIALS_PATH}" \
    php "${SCRIPT_DIR}/seed.php"; then
    seed_ok=1
    break
  fi
  sleep 3
done

if [[ "${seed_ok}" -ne 1 ]]; then
  echo "Zitadel seed failed" >&2
  docker logs "${ZITADEL_CONTAINER}" >&2 || true
  exit 1
fi

CLIENT_ID="$(php -r 'echo json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR)["client_id"];' "${CREDENTIALS_PATH}")"
CLIENT_SECRET="$(php -r 'echo json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR)["client_secret"];' "${CREDENTIALS_PATH}")"

cat > "${RUN_STATE_DIR}/env.sh" <<EOF
export ZITADEL_URL='${ZITADEL_URL}'
export ZITADEL_CREDENTIALS='${CREDENTIALS_PATH}'
export ZITADEL_CLIENT_ID='${CLIENT_ID}'
export ZITADEL_CLIENT_SECRET='${CLIENT_SECRET}'
export ZITADEL_PORT='${ZITADEL_PORT}'
export ZITADEL_CONTAINER='${ZITADEL_CONTAINER}'
export ZITADEL_DB_CONTAINER='${DB_CONTAINER}'
export ZITADEL_NETWORK_NAME='${NETWORK_NAME}'
export PACKAGE_ROOT='${PACKAGE_ROOT}'
EOF

echo "Prepared Zitadel at ${ZITADEL_URL} (credentials: ${CREDENTIALS_PATH})"
echo "Source ${RUN_STATE_DIR}/env.sh then: vendor/bin/pest --group=zitadel"
