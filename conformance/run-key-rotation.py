#!/usr/bin/env python3
"""
Run the two Config RP key-rotation modules, which the suite's run-test-plan.py skips.

Usage (in the runner container, with rp-driver.py running): run-key-rotation.py PLAN_ID MODULE...
PLAN_ID is the id of the oidcc-client-config-certification-test-plan created by run-rp-plan.sh.
Run oidcc-client-test-signing-key-rotation with RP_SECOND_LOGIN=1 on the driver and
oidcc-client-test-signing-key-rotation-just-before-signing without it.
"""

from __future__ import annotations

import json
import os
import sys
import time

import httpx

SUITE = os.environ.get("CONFORMANCE_SERVER", "https://nginx:8443/").rstrip("/")


def main() -> int:
    plan_id, module_names = sys.argv[1], sys.argv[2:]
    has_failed = False

    with httpx.Client(verify=False, timeout=30) as suite_api:
        for module_name in module_names:
            created = suite_api.post(
                f"{SUITE}/api/runner",
                params={"test": module_name, "plan": plan_id, "variant": json.dumps({"response_type": "code"})},
            )
            test_id = created.json()["id"]
            deadline = time.time() + 240
            test_info: dict = {}

            while time.time() < deadline:
                test_info = suite_api.get(f"{SUITE}/api/info/{test_id}").json()

                if test_info.get("status") in ("FINISHED", "INTERRUPTED"):
                    break

                time.sleep(2)

            print(module_name, test_id, test_info.get("status"), test_info.get("result"), flush=True)
            has_failed = has_failed or test_info.get("result") not in ("PASSED", "REVIEW")

    return 1 if has_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
