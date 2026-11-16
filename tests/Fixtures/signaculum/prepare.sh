#!/usr/bin/env bash
# Prepare a throwaway Signaculum IdP for `pest --group=signaculum`.
# Does not touch Herd sites, the main checkouts' .env, or their databases.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

SIGNACULUM_DIR="${SIGNACULUM_DIR:?Set SIGNACULUM_DIR to a Signaculum checkout}"
SIGNACULUM_URL="${SIGNACULUM_URL:-http://127.0.0.1:8090}"
SIGNACULUM_PORT="${SIGNACULUM_PORT:-8090}"
BACKCHANNEL_PORT="${BACKCHANNEL_PORT:-8091}"
RUN_STATE_DIR="${SIGNACULUM_RUN_STATE_DIR:-${TMPDIR:-/tmp}/laravel-oidc-signaculum-run}"
CREDENTIALS_PATH="${SIGNACULUM_CREDENTIALS:-${RUN_STATE_DIR}/credentials.json}"
CAPTURE_PATH="${SIGNACULUM_BACKCHANNEL_CAPTURE:-${RUN_STATE_DIR}/logout-token.txt}"

mkdir -p "${RUN_STATE_DIR}"
rm -f "${CAPTURE_PATH}" "${CREDENTIALS_PATH}"

cd "${SIGNACULUM_DIR}"

if [[ ! -f vendor/autoload.php ]]; then
  composer install --no-interaction --prefer-dist
fi

# Inertia login needs a Vite manifest. Prefer an existing build (local main
# checkout or a previous CI artifact); otherwise build with Node 24.
if [[ ! -f public/build/manifest.json ]]; then
  if [[ -n "${SIGNACULUM_VITE_BUILD:-}" && -f "${SIGNACULUM_VITE_BUILD}/manifest.json" ]]; then
    ln -sfn "${SIGNACULUM_VITE_BUILD}" public/build
  else
    export PATH="${HOME}/.nvm/versions/node/v24.22.1/bin:${PATH}"
    npm ci
    npm run build
  fi
fi

# Isolated SQLite + sync queue so back-channel logout POSTs immediately.
export APP_ENV=local
export APP_DEBUG=true
export APP_URL="${SIGNACULUM_URL}"
export OIDC_ISSUER="${SIGNACULUM_URL}"
export DB_CONNECTION=sqlite
export DB_DATABASE="${SIGNACULUM_DIR}/database/e2e-signaculum.sqlite"
export QUEUE_CONNECTION=sync
export SESSION_DRIVER=file
export CACHE_STORE=file
export BROADCAST_CONNECTION=null
export MAIL_MAILER=array

: > "${DB_DATABASE}"

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

# Force the throwaway values into .env without interactive install.
php -r '
$path = ".env";
$env = file_get_contents($path);
$pairs = [
  "APP_ENV" => "local",
  "APP_DEBUG" => "true",
  "APP_URL" => getenv("APP_URL"),
  "DB_CONNECTION" => "sqlite",
  "DB_DATABASE" => getenv("DB_DATABASE"),
  "QUEUE_CONNECTION" => "sync",
  "SESSION_DRIVER" => "file",
  "CACHE_STORE" => "file",
  "BROADCAST_CONNECTION" => "null",
  "MAIL_MAILER" => "array",
];
foreach ($pairs as $key => $value) {
  if (preg_match("/^{$key}=.*/m", $env) === 1) {
    $env = preg_replace("/^{$key}=.*/m", $key."=".$value, $env, 1);
  } else {
    $env .= PHP_EOL.$key."=".$value.PHP_EOL;
  }
}
file_put_contents($path, $env);
'

php artisan key:generate --force --no-interaction
php artisan migrate --force --no-interaction
php artisan passport:keys --force --no-interaction
php artisan signaculum:rotate-signing-key --no-interaction

SIGNACULUM_DIR="${SIGNACULUM_DIR}" \
SIGNACULUM_URL="${SIGNACULUM_URL}" \
SIGNACULUM_BACKCHANNEL_URI="http://127.0.0.1:${BACKCHANNEL_PORT}/backchannel-logout" \
SIGNACULUM_REDIRECT_URI="http://localhost/auth/oidc/callback" \
SIGNACULUM_POST_LOGOUT_REDIRECT_URI="http://localhost/" \
SIGNACULUM_CREDENTIALS="${CREDENTIALS_PATH}" \
php "${SCRIPT_DIR}/seed-idp.php"

# Export helpers for the caller (CI step or local shell).
cat > "${RUN_STATE_DIR}/env.sh" <<EOF
export SIGNACULUM_URL='${SIGNACULUM_URL}'
export SIGNACULUM_CREDENTIALS='${CREDENTIALS_PATH}'
export SIGNACULUM_BACKCHANNEL_CAPTURE='${CAPTURE_PATH}'
export SIGNACULUM_PORT='${SIGNACULUM_PORT}'
export BACKCHANNEL_PORT='${BACKCHANNEL_PORT}'
export SIGNACULUM_DIR='${SIGNACULUM_DIR}'
export PACKAGE_ROOT='${PACKAGE_ROOT}'
EOF

# shellcheck disable=SC1090
source "${RUN_STATE_DIR}/env.sh"

CLIENT_ID="$(php -r 'echo json_decode(file_get_contents(getenv("SIGNACULUM_CREDENTIALS")), true, 512, JSON_THROW_ON_ERROR)["client_id"];')"
CLIENT_SECRET="$(php -r 'echo json_decode(file_get_contents(getenv("SIGNACULUM_CREDENTIALS")), true, 512, JSON_THROW_ON_ERROR)["client_secret"];')"
ORG_SLUG="$(php -r 'echo json_decode(file_get_contents(getenv("SIGNACULUM_CREDENTIALS")), true, 512, JSON_THROW_ON_ERROR)["organization_slug"];')"
TOTP_SECRET="$(php -r 'echo json_decode(file_get_contents(getenv("SIGNACULUM_CREDENTIALS")), true, 512, JSON_THROW_ON_ERROR)["users"]["mfa"]["totp_secret"];')"

cat >> "${RUN_STATE_DIR}/env.sh" <<EOF
export SIGNACULUM_CLIENT_ID='${CLIENT_ID}'
export SIGNACULUM_CLIENT_SECRET='${CLIENT_SECRET}'
export SIGNACULUM_ORG_SLUG='${ORG_SLUG}'
export SIGNACULUM_TOTP_SECRET='${TOTP_SECRET}'
EOF

echo "Prepared Signaculum at ${SIGNACULUM_URL} (credentials: ${CREDENTIALS_PATH})"
echo "Source ${RUN_STATE_DIR}/env.sh then start the servers (see README comment in SignaculumTest.php)."
