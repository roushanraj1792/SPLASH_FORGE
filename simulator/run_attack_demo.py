"""
SentinelX — Master Attack Scenario Demo Runner
CLI tool for live SOC demonstrations and attack simulation.
Supports standalone scenarios or full multi-stage attack campaign.
"""

import argparse
import sys
import os
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from simulator.event_generator import simulate_brute_force
from simulator.port_scan_simulator import simulate_port_scan
from simulator.suspicious_auth_simulator import simulate_suspicious_authentication
from simulator.privilege_escalation_simulator import generate_privilege_escalation_events
from simulator.suspicious_powershell_simulator import generate_suspicious_powershell_events

SCENARIOS = {
    "brute_force": {
        "title": "T1110: Password Brute Force Attack",
        "description": "5 failed login attempts in rapid succession from 192.168.1.101 against user 'admin'",
        "runner": simulate_brute_force,
        "mitre": "T1110 (Credential Access - Brute Force)",
        "expected_severity": "MEDIUM / HIGH"
    },
    "port_scan": {
        "title": "T1046: Network Service Discovery (Port Scan)",
        "description": "Rapid probing across 10 common ports (21, 22, 23, 25, 53, 80, 110, 135, 443, 445) from 192.168.1.61",
        "runner": simulate_port_scan,
        "mitre": "T1046 (Discovery - Network Service Scanning)",
        "expected_severity": "MEDIUM"
    },
    "suspicious_auth": {
        "title": "T1078: Suspicious Authentication Anomaly",
        "description": "Bursts of rapid successful logins from external IP 192.168.1.70",
        "runner": simulate_suspicious_authentication,
        "mitre": "T1078 (Valid Accounts)",
        "expected_severity": "MEDIUM"
    },
    "privilege_escalation": {
        "title": "T1068: Privilege Escalation Attempt",
        "description": "Unauthorized permission changes and root/admin token elevation from 192.168.1.80",
        "runner": generate_privilege_escalation_events,
        "mitre": "T1068 (Privilege Escalation)",
        "expected_severity": "HIGH / CRITICAL"
    },
    "powershell": {
        "title": "T1059.001: Suspicious PowerShell Obfuscation",
        "description": "PowerShell execution with ExecutionPolicy Bypass and EncodedCommand from 192.168.1.90",
        "runner": generate_suspicious_powershell_events,
        "mitre": "T1059.001 (Execution - PowerShell)",
        "expected_severity": "HIGH"
    }
}


def print_banner():
    print("""
================================================================================
                    SENTINELX - ATTACK DEMO SUITE
               Autonomous Threat Detection & Mini-SIEM
================================================================================
    """)


def run_scenario(name):
    meta = SCENARIOS.get(name)
    if not meta:
        print(f"[!] Unknown scenario: {name}")
        return False

    print(f"\n[>>> LAUNCHING ATTACK SCENARIO: {meta['title']} <<<]")
    print(f"[*] Narrative: {meta['description']}")
    print(f"[*] MITRE ATT&CK: {meta['mitre']}")
    print(f"[*] Expected Alert Severity: {meta['expected_severity']}")
    print("-" * 70)

    start_time = time.time()
    try:
        meta["runner"]()
        elapsed = time.time() - start_time
        print("-" * 70)
        print(f"[+] Scenario '{name}' injected successfully in {elapsed:.2f}s.")
        print("[+] Check SentinelX Web UI:")
        print("    -> Live Events: View raw telemetry log")
        print("    -> Security Alerts: View normalized alert & risk score")
        print("    -> Incidents: View incident timeline & AI Copilot analysis")
        print("    -> MITRE ATT&CK: View mapped technique")
        return True
    except Exception as e:
        print(f"[-] Error executing scenario '{name}': {e}")
        return False


def run_all():
    print("\n[>>> LAUNCHING FULL MULTI-STAGE ATTACK CAMPAIGN <<<]")
    for idx, (name, meta) in enumerate(SCENARIOS.items(), start=1):
        print(f"\n--- Stage {idx}/5: {meta['title']} ---")
        meta["runner"]()
        time.sleep(1)
    print("\n[+] Full attack campaign simulated. Refresh SentinelX UI to observe correlated telemetry.")


def interactive_menu():
    print_banner()
    print("Available Scenarios:")
    keys = list(SCENARIOS.keys())
    for idx, key in enumerate(keys, start=1):
        meta = SCENARIOS[key]
        print(f"  [{idx}] {meta['title']}")
        print(f"      MITRE: {meta['mitre']} | Target: {meta['description'][:60]}...")
    print(f"  [{len(keys) + 1}] ALL Scenarios (Full Multi-Stage Attack Campaign)")
    print("  [0] Exit")

    choice = input("\nSelect scenario to simulate [0-6]: ").strip()
    if choice == "0":
        print("Exiting.")
        return
    elif choice in [str(i) for i in range(1, len(keys) + 1)]:
        key = keys[int(choice) - 1]
        run_scenario(key)
    elif choice == str(len(keys) + 1) or choice.lower() == "all":
        run_all()
    else:
        print("[!] Invalid selection.")


def main():
    parser = argparse.ArgumentParser(
        description="SentinelX Master Attack Demo Runner"
    )
    parser.add_argument(
        "--scenario",
        choices=["brute_force", "port_scan", "suspicious_auth", "privilege_escalation", "powershell", "all"],
        help="Specific attack scenario to simulate"
    )
    args = parser.parse_args()

    if args.scenario:
        print_banner()
        if args.scenario == "all":
            run_all()
        else:
            run_scenario(args.scenario)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
