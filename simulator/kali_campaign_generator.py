"""
Kali Campaign Generator — Bounded Laboratory Red-Team Traffic Simulator
========================================================================
Part of the SentinelX Red-to-Blue Security Laboratory.

Role:
  Simulates controlled, bounded Red-Team traffic originating from Kali Linux
  targeting an explicitly authorized laboratory target (Web-01).

Safety & Security Boundary Rules:
  - Target URL is strictly validated against an authorized private lab whitelist.
  - Communicates ONLY with Web-01 (never directly with SentinelX).
  - Hard limit: Maximum 100 requests (Phase 1 limit).
  - Hard limit: Maximum 10 requests per second.
  - Zero destructive payloads, zero malware, zero shellcode, zero exploits.
  - Generates synthetic, realistic HTTP traffic to test Blue-Team detection.
"""

import argparse
import ipaddress
import json
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests


# Phase 1 Hard Boundary Guardrails
MAX_ALLOWED_REQUESTS = 100
MAX_ALLOWED_RATE = 10.0  # requests per second
DEFAULT_TARGET = "http://192.168.56.30:8080"
DEFAULT_TIMEOUT = 5.0


class SecurityViolation(Exception):
    """Raised when an attempt is made to target unauthorized or public infrastructure."""
    pass


AUTHORIZED_LAB_HOST = "192.168.56.30"
AUTHORIZED_LAB_PORT = 8080


def validate_target_url(target_url: str, allow_test_target: bool = False) -> str:
    """
    Ensure the target URL conforms strictly to the authorized laboratory safety boundary.
    The ONLY permitted live target is: http://192.168.56.30:8080.
    Rejects all other destinations:
      - localhost
      - 127.0.0.1
      - 10.0.2.x
      - other 192.168.x.x addresses
      - 10.x.x.x
      - 172.16.x.x
      - public IPs and domains
      - 192.168.56.30 with any port other than 8080
    """
    if not target_url:
        raise SecurityViolation("Target URL must not be empty.")

    parsed = urlparse(target_url.strip())

    if parsed.scheme not in ["http", "https"]:
        raise SecurityViolation(f"Unauthorized protocol: '{parsed.scheme}'. Only http/https permitted.")

    hostname = parsed.hostname
    port = parsed.port

    if not hostname:
        raise SecurityViolation(f"Invalid target URL: missing hostname in '{target_url}'.")

    if allow_test_target:
        # Internal test harness only
        port_str = f":{port}" if port else ""
        return f"{parsed.scheme}://{hostname}{port_str}"

    if hostname != AUTHORIZED_LAB_HOST:
        raise SecurityViolation(
            f"SECURITY VIOLATION: Target host '{hostname}' is strictly prohibited! "
            f"The ONLY permitted live target in Phase 1 is {AUTHORIZED_LAB_HOST}:{AUTHORIZED_LAB_PORT}. "
            "Localhost, 127.0.0.1, other private subnets, and public destinations are rejected."
        )

    if port != AUTHORIZED_LAB_PORT:
        raise SecurityViolation(
            f"SECURITY VIOLATION: Target port '{port}' is prohibited! "
            f"Target must specifically be port {AUTHORIZED_LAB_PORT}. Found: {port}."
        )

    return f"{parsed.scheme}://{hostname}:{port}"


def build_scenario_plan(scenario: str, total_count: int) -> List[Dict[str, Any]]:
    """
    Build the sequence of requests to transmit.
    Phase 1 Scenario: 90 benign requests + 10 controlled failed logins.
    """
    plan = []

    if scenario == "initial-demo":
        # Enforce exact 90 benign / 10 failed login composition
        failed_logins_count = min(10, total_count)
        benign_count = total_count - failed_logins_count

        # 1. Benign Phase
        benign_paths = ["/", "/api/v1/health", "/search?q=status"]
        for i in range(benign_count):
            path = benign_paths[i % len(benign_paths)]
            plan.append({
                "method": "GET",
                "path": path,
                "payload": None,
                "description": f"Benign probe #{i + 1} ({path})"
            })

        # 2. Controlled Failed Logins Phase (Triggers T1110 Brute Force in SentinelX)
        for i in range(failed_logins_count):
            plan.append({
                "method": "POST",
                "path": "/api/v1/login",
                "payload": {
                    "username": "admin",
                    "password": f"SyntheticLabTestPass{i + 1}!"
                },
                "description": f"Controlled failed login attempt #{i + 1} (admin)"
            })

    elif scenario == "auth-only":
        # Pure authentication failure test
        for i in range(total_count):
            plan.append({
                "method": "POST",
                "path": "/api/v1/login",
                "payload": {
                    "username": "admin",
                    "password": f"SyntheticAuthTest{i + 1}!"
                },
                "description": f"Authentication attempt #{i + 1}"
            })

    elif scenario == "benign-only":
        # Pure benign portal browsing
        for i in range(total_count):
            plan.append({
                "method": "GET",
                "path": "/" if i % 2 == 0 else "/api/v1/health",
                "payload": None,
                "description": f"Benign portal request #{i + 1}"
            })

    else:
        raise ValueError(f"Unknown scenario: '{scenario}'. Supported: 'initial-demo', 'auth-only', 'benign-only'.")

    return plan


def run_generator(
    target_url: str,
    scenario: str = "initial-demo",
    count: int = 100,
    rate: float = 10.0,
    timeout: float = DEFAULT_TIMEOUT,
    dry_run: bool = False,
    allow_test_target: bool = False
) -> Dict[str, Any]:
    """
    Execute the controlled laboratory traffic generator.
    """
    # Enforce strict target safety
    base_url = validate_target_url(target_url, allow_test_target=allow_test_target)

    # Enforce Phase 1 hard boundary limits
    actual_count = min(max(1, int(count)), MAX_ALLOWED_REQUESTS)
    actual_rate = min(max(0.1, float(rate)), MAX_ALLOWED_RATE)
    inter_request_sleep = 1.0 / actual_rate

    print("=" * 65)
    print("  KALI CAMPAIGN GENERATOR — RED-TEAM LAB SIMULATOR")
    print("=" * 65)
    print(f"Validated Target    : {base_url}")
    print(f"Scenario Name       : {scenario}")
    print(f"Total Requests      : {actual_count} (Phase 1 limit: {MAX_ALLOWED_REQUESTS})")
    print(f"Transmission Rate   : {actual_rate} req/s (delay: {inter_request_sleep:.3f}s)")
    print(f"Dry-Run Mode        : {'ACTIVE (No network packets will be sent)' if dry_run else 'NO (Live transmission)'}")
    print("=" * 65)

    plan = build_scenario_plan(scenario, actual_count)

    session = requests.Session()
    session.headers.update({
        "User-Agent": "SentinelX-Lab-Kali/1.0",
        "X-Lab-Scenario": scenario,
        "X-Lab-Campaign-ID": "CAMP-2026-001"
    })

    status_counts: Dict[int, int] = {}
    errors: List[str] = []
    start_time = time.time()

    for idx, item in enumerate(plan, 1):
        url = f"{base_url}{item['path']}"
        method = item["method"]
        payload = item["payload"]
        desc = item["description"]

        if dry_run:
            print(f"[DRY-RUN {idx:03d}/{actual_count:03d}] {method} {url} | {desc}")
            time.sleep(min(inter_request_sleep, 0.05))  # Fast mock delay in dry-run
            status_counts[200 if "Benign" in desc else 401] = status_counts.get(200 if "Benign" in desc else 401, 0) + 1
            continue

        try:
            if method == "POST":
                resp = session.post(url, json=payload, timeout=timeout)
            else:
                resp = session.get(url, timeout=timeout)

            status = resp.status_code
            status_counts[status] = status_counts.get(status, 0) + 1
            print(f"[{idx:03d}/{actual_count:03d}] {method} {item['path']} -> HTTP {status} | {desc}")

        except Exception as exc:
            err_msg = str(exc)
            errors.append(f"Request #{idx} error: {err_msg}")
            print(f"[{idx:03d}/{actual_count:03d}] {method} {item['path']} -> ERROR: {err_msg[:60]}")

        # Enforce rate-limiting delay
        if idx < actual_count:
            time.sleep(inter_request_sleep)

    total_time = max(0.001, time.time() - start_time)
    effective_rate = actual_count / total_time

    print("\n" + "=" * 65)
    print("  SIMULATION RUN COMPLETE")
    print("=" * 65)
    print(f"Target              : {base_url}")
    print(f"Total Transmitted   : {actual_count}")
    print(f"Elapsed Time        : {total_time:.2f} seconds")
    print(f"Effective Rate      : {effective_rate:.2f} req/s")
    print("Status Breakdown    :")
    for code, cnt in sorted(status_counts.items()):
        print(f"  HTTP {code:3d} : {cnt} requests")
    if errors:
        print(f"Errors Encountered  : {len(errors)}")
    print("=" * 65 + "\n")

    return {
        "target": base_url,
        "scenario": scenario,
        "total_requests": actual_count,
        "status_counts": status_counts,
        "elapsed_seconds": total_time,
        "effective_rate": effective_rate,
        "errors": errors,
        "dry_run": dry_run
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kali Campaign Generator — Bounded Laboratory Red-Team Simulator")
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"Web-01 Target URL (default: {DEFAULT_TARGET})")
    parser.add_argument("--scenario", default="initial-demo", choices=["initial-demo", "auth-only", "benign-only"], help="Scenario profile")
    parser.add_argument("--count", type=int, default=100, help=f"Total requests to send (max: {MAX_ALLOWED_REQUESTS})")
    parser.add_argument("--rate", type=float, default=10.0, help=f"Requests per second (max: {MAX_ALLOWED_RATE})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Print planned requests without network transmission")
    args = parser.parse_args()

    try:
        result = run_generator(
            target_url=args.target,
            scenario=args.scenario,
            count=args.count,
            rate=args.rate,
            timeout=args.timeout,
            dry_run=args.dry_run
        )
        if result["errors"]:
            sys.exit(1)
        sys.exit(0)
    except SecurityViolation as sec_err:
        print(f"\n[FATAL SECURITY ERROR] {sec_err}", file=sys.stderr)
        sys.exit(2)
    except Exception as general_err:
        print(f"\n[FATAL ERROR] {general_err}", file=sys.stderr)
        sys.exit(3)
