#!/bin/sh
# Run one RP test plan in the runner container, with the driver beside it.
# Usage: run-rp-plan.sh <alias> <plan-with-variants> [logout] [second-login]
# The harness app must be started with the same RP_ALIAS (see docs/conformance/openid.md).
set -u
alias_name="$1"
plan="$2"
sed "s/RP_ALIAS/${alias_name}/g" /laravel-oidc/conformance/rp-config.json > "/tmp/${alias_name}.json"
RP_DO_LOGOUT="${3:-}" RP_SECOND_LOGIN="${4:-}" python /laravel-oidc/conformance/rp-driver.py > "/results/rp-driver-${alias_name}.log" 2>&1 &
driver_pid=$!
cd /conformance-suite
python scripts/run-test-plan.py --export-dir /results "${plan}" "/tmp/${alias_name}.json" > "/results/runner-${alias_name}.log" 2>&1
plan_status=$?
kill "${driver_pid}"
echo "exit=${plan_status} ${alias_name}"
