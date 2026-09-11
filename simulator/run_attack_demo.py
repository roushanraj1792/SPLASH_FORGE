"""
SentinelX — Master Attack Scenario Demo Runner
CLI tool for live two-teammate SOC attack demonstrations.

TEAMMATE A = Attacker / Demo Operator (runs this CLI in terminal)
TEAMMATE B = SOC Analyst / Presenter (views live pipeline in browser at http://localhost:8501)

Authorized local testing only. Never targets public systems or third parties.
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
    "1": {
        "key": "brute_force",
        "name": "Password Brute Force Attack",
        "source_ip": "192.168.1.101",
        "expected_events": 5,
        "detector": "detect_brute_force",
        "mitre": "T1110 (Credential Access - Brute Force)",
        "expected_severity": "HIGH",
        "expected_risk": "80 / 100",
        "runner": simulate_brute_force,
        "description": "5 rapid failed login attempts against 'admin' from unauthorized IP."
    },
    "2": {
        "key": "port_scan",
        "name": "Network Service Port Scan",
        "source_ip": "192.168.1.61",
        "expected_events": 10,
        "detector": "detect_port_scan",
        "mitre": "T1046 (Discovery - Network Service Scanning)",
        "expected_severity": "MEDIUM",
        "expected_risk": "50 / 100",
        "runner": simulate_port_scan,
        "description": "Port enumeration probing 10 distinct TCP/UDP service ports."
    },
    "3": {
        "key": "suspicious_auth",
        "name": "Suspicious Authentication Anomaly",
        "source_ip": "192.168.1.70",
        "expected_events": 5,
        "detector": "detect_suspicious_authentication",
        "mitre": "T1078 (Valid Accounts)",
        "expected_severity": "MEDIUM",
        "expected_risk": "50 / 100",
        "runner": simulate_suspicious_authentication,
        "description": "Rapid succession of 5 successful admin logins from external host."
    },
    "4": {
        "key": "privilege_escalation",
        "name": "Privilege Escalation Attempt",
        "source_ip": "192.168.1.80",
        "expected_events": 3,
        "detector": "detect_privilege_escalation",
        "mitre": "T1068 (Privilege Escalation)",
        "expected_severity": "HIGH",
        "expected_risk": "80 / 100",
        "runner": generate_privilege_escalation_events,
        "description": "3 unauthorized security permission changes and admin token elevation."
    },
    "5": {
        "key": "powershell",
        "name": "Suspicious Obfuscated PowerShell",
        "source_ip": "192.168.1.90",
        "expected_events": 2,
        "detector": "detect_suspicious_powershell",
        "mitre": "T1059.001 (Execution - PowerShell)",
        "expected_severity": "HIGH",
        "expected_risk": "80 / 100",
        "runner": generate_suspicious_powershell_events,
        "description": "PowerShell execution with ExecutionPolicy Bypass and EncodedCommand."
    }
}

KEY_MAP = {
    "brute_force": "1",
    "port_scan": "2",
    "suspicious_auth": "3",
    "privilege_escalation": "4",
    "powershell": "5"
}


def print_banner():
    print("""
================================================================================
                    SENTINELX — ATTACK DEMONSTRATION SUITE
             Autonomous Threat Detection & Security Operations Center
================================================================================
  Roles:
    [TEAMMATE A] Attacker / Demo Operator (Running this terminal command)
    [TEAMMATE B] SOC Analyst / Presenter  (Observing web UI at http://localhost:8501)
--------------------------------------------------------------------------------
""")


def execute_scenario(scenario_id):
    scenario = SCENARIOS.get(str(scenario_id))
    if not scenario:
        print(f"[!] Invalid scenario selection: {scenario_id}")
        return False

    print(f"\n[>>> LAUNCHING SCENARIO [{scenario_id}]: {scenario['name']} <<<]")
    print(f"  • Description        : {scenario['description']}")
    print(f"  • Test Source IP     : {scenario['source_ip']}")
    print(f"  • Expected Events    : {scenario['expected_events']}")
    print(f"  • Expected Detector  : {scenario['detector']}")
    print(f"  • MITRE ATT&CK       : {scenario['mitre']}")
    print(f"  • Expected Risk/Sev  : {scenario['expected_severity']} ({scenario['expected_risk']})")
    print("-" * 75)

    start_time = time.time()
    try:
        event_ids = scenario["runner"]()
        elapsed = time.time() - start_time

        print("-" * 75)
        print(f"[✓] Attack injection completed in {elapsed:.2f}s.")
        print(f"[✓] Scenario Name     : {scenario['name']}")
        print(f"[✓] Events Generated  : {len(event_ids) if event_ids else scenario['expected_events']}")
        print(f"[✓] Test Source IP    : {scenario['source_ip']}")
        if event_ids:
            print(f"[✓] Recorded Event IDs: {event_ids}")
        print(f"[✓] Expected Detector : {scenario['detector']}")
        print(f"[✓] MITRE Technique   : {scenario['mitre']}")
        print("\n[>>> INSTRUCTIONS FOR TEAMMATE B (SOC PRESENTER) <<<]")
        print("  1. In SentinelX browser, click '🔄 Refresh Telemetry'")
        print("  2. Navigate to 'Live Events': Observe raw ingested telemetry events")
        print("  3. Navigate to 'Security Alerts': Verify normalized alert and risk score")
        print("  4. Navigate to 'Incidents': Review correlated incident, lifecycle state, and AI Copilot analysis")
        print("  5. Navigate to 'MITRE ATT&CK': Confirm technique matrix mapping")
        print("  6. Navigate to 'Audit Logs': Confirm automated containment mitigation if High/Critical")
        print("-" * 75)
        return True
    except Exception as err:
        print(f"[!] Execution failed: {err}")
        return False


def execute_full_demo():
    print("\n[>>> LAUNCHING [6] FULL MULTI-STAGE ATTACK CAMPAIGN <<<]")
    print("[*] Executing all 5 attack scenarios in sequential kill-chain order...")
    for step in ["1", "2", "3", "4", "5"]:
        execute_scenario(step)
        time.sleep(1)
    print("\n[✓] FULL MULTI-STAGE CAMPAIGN COMPLETED SUCCESSFULLY.")
    print("[*] Teammate B: Click '🔄 Refresh Telemetry' in SentinelX to observe complete multi-stage correlation.")


def show_interactive_menu():
    print_banner()
    print("Available Scenarios:")
    print("  [1] Brute Force                 (T1110: 5 Failed Logins)")
    print("  [2] Port Scan                   (T1046: 10 Port Probes)")
    print("  [3] Suspicious Authentication   (T1078: 5 Rapid Valid Logins)")
    print("  [4] Privilege Escalation        (T1068: 3 Privilege Changes)")
    print("  [5] Suspicious PowerShell       (T1059.001: Obfuscated Commands)")
    print("  [6] Full Demo                   (Complete Multi-Stage Attack Campaign)")
    print("  [0] Exit")

    choice = input("\nSelect scenario to simulate [0-6]: ").strip()
    if choice == "0":
        print("Exiting demo runner.")
        return
    elif choice in ["1", "2", "3", "4", "5"]:
        execute_scenario(choice)
    elif choice == "6" or choice.lower() in ["all", "full"]:
        execute_full_demo()
    else:
        print("[!] Invalid selection.")


def main():
    parser = argparse.ArgumentParser(
        description="SentinelX Master Attack Demo Runner"
    )
    parser.add_argument(
        "--scenario",
        help="Select scenario by number [1-6] or name (brute_force, port_scan, suspicious_auth, privilege_escalation, powershell, all)"
    )
    args = parser.parse_args()

    if args.scenario:
        print_banner()
        scen = args.scenario.strip().lower()
        if scen in KEY_MAP:
            execute_scenario(KEY_MAP[scen])
        elif scen in ["1", "2", "3", "4", "5"]:
            execute_scenario(scen)
        elif scen in ["6", "all", "full"]:
            execute_full_demo()
        else:
            print(f"[!] Unknown scenario: {args.scenario}")
    else:
        show_interactive_menu()


if __name__ == "__main__":
    main()
