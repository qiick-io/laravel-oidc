#!/usr/bin/env python3
"""
Drive the laravel-oidc harness RP whenever an OpenID Foundation RP-test module waits for it.

The suite's RP modules act as the OpenID Provider and wait for the relying party to start
a login. This worker polls the suite for waiting `oidcc-client-*` modules and, for each one,
signs in through the harness app (and signs out again for the logout plans). It writes one
evidence line per step to /results/rp-evidence.log; the harness app's Laravel log holds the
reason each refused token was refused.

Environment:
  RP_BASE          harness app URL as the suite network sees it (default http://rp:8000)
  RP_DO_LOGOUT     "1" for the logout plans: log in and out in Chromium
  RP_SECOND_LOGIN  "1" for oidcc-client-test-signing-key-rotation: a second login with the
                   RP cache kept, so the RP must refetch the rotated JWKS
"""

from __future__ import annotations

import os
import time

import httpx

SUITE = os.environ.get("CONFORMANCE_SERVER", "https://nginx:8443/").rstrip("/")
RP = os.environ.get("RP_BASE", "http://rp:8000")
SELENIUM = os.environ.get("SELENIUM_REMOTE_URL", "http://chrome:4444/wd/hub")
SHOULD_LOG_OUT = os.environ.get("RP_DO_LOGOUT") == "1"
SHOULD_LOG_IN_TWICE = os.environ.get("RP_SECOND_LOGIN") == "1"

# These Config RP modules end as soon as the RP has fetched discovery (and the JWKS); a
# login after that reaches a finished module and is reported as an illegal state change.
DISCOVERY_ONLY_MODULES = {
    "oidcc-client-test-discovery-openid-config",
    "oidcc-client-test-discovery-jwks-uri-keys",
}

handled_test_ids: set[str] = set()
evidence_file = open("/results/rp-evidence.log", "a", encoding="utf-8")


def record_evidence(test_id: str, module_name: str, text: str) -> None:
    line = f"{time.strftime('%H:%M:%S')} {test_id} {module_name}: {text}"
    print(line, flush=True)
    evidence_file.write(line + "\n")
    evidence_file.flush()


def log_in_and_out_in_browser(test_id: str, module_name: str) -> None:
    """The suite's end-session page runs JavaScript and front-channel iframes."""
    from selenium import webdriver
    from selenium.webdriver import ChromeOptions

    options = ChromeOptions()
    options.add_argument("--ignore-certificate-errors")
    # The harness RP is plain http, framed by the suite's https front-channel page.
    options.add_argument("--allow-running-insecure-content")
    browser = webdriver.Remote(command_executor=SELENIUM, options=options)

    try:
        browser.get(f"{RP}/auth/oidc/redirect")
        time.sleep(2)
        body_text = browser.find_element("tag name", "body").text
        record_evidence(test_id, module_name, f"login -> {browser.current_url} {body_text[:150]!r}")

        if "RP-LOGGED-IN" not in body_text:
            return

        browser.get(f"{RP}/logout")
        deadline = time.time() + 30

        while time.time() < deadline and not browser.current_url.startswith(RP):
            time.sleep(1)

        time.sleep(2)
        body_text = browser.find_element("tag name", "body").text
        record_evidence(test_id, module_name, f"logout -> {browser.current_url} {body_text[:200]!r}")
    finally:
        browser.quit()


def drive_relying_party(test_id: str, module_name: str) -> None:
    with httpx.Client(verify=False, follow_redirects=True, timeout=30) as client:
        # Each module publishes fresh signing keys; a real IdP does not rotate every few seconds.
        client.get(f"{RP}/harness/reset")

        if module_name in DISCOVERY_ONLY_MODULES:
            response = client.get(f"{RP}/harness/discover")
            record_evidence(test_id, module_name, f"discover -> {response.status_code}")

            return

        if SHOULD_LOG_OUT:
            log_in_and_out_in_browser(test_id, module_name)

            return

        response = client.get(f"{RP}/auth/oidc/redirect")
        record_evidence(test_id, module_name, f"login -> {response.url} {response.text[:200]!r}")

    if SHOULD_LOG_IN_TWICE and "RP-LOGGED-IN" in response.text:
        with httpx.Client(verify=False, follow_redirects=True, timeout=30) as second_client:
            response = second_client.get(f"{RP}/auth/oidc/redirect")
            record_evidence(test_id, module_name, f"second login -> {response.url} {response.text[:200]!r}")


def main() -> None:
    with httpx.Client(verify=False, timeout=15) as suite_api:
        while True:
            try:
                for test_id in suite_api.get(f"{SUITE}/api/runner/running").json():
                    if test_id in handled_test_ids:
                        continue

                    status_response = suite_api.get(f"{SUITE}/api/info/{test_id}")

                    if status_response.status_code != 200 or not status_response.content:
                        continue

                    test_info = status_response.json()
                    module_name = str(test_info.get("testName", ""))

                    if test_info.get("status") != "WAITING" or not module_name.startswith("oidcc-client"):
                        continue

                    handled_test_ids.add(test_id)

                    try:
                        drive_relying_party(test_id, module_name)
                    except Exception as error:  # noqa: BLE001 - one module must not stop the worker
                        record_evidence(test_id, module_name, f"driver error {error!r}")
            except Exception as error:  # noqa: BLE001 - the suite restarts between plans
                print("poll error", error, flush=True)

            time.sleep(1)


if __name__ == "__main__":
    main()
