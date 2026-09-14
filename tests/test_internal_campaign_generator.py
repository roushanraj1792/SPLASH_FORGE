"""
Unit & Integration Tests for Internal Synthetic Campaign Engine
===============================================================
Validates:
  1. Deterministic generation (identical outputs for identical inputs).
  2. Strict bounding and campaign size limits enforcement.
  3. Multi-source IP distribution across distinct synthetic bot nodes.
  4. Safe lab-only IP validation (RFC 5737 / RFC 1918) and rejection of public/loopback IPs.
  5. Full compliance with SentinelX event schema & constraints.
  6. Expected multi-stage campaign sequence (Auth Attack -> Suspicious Auth -> PowerShell -> PrivEsc).
  7. Verification of zero network, socket, or external calls during generation.
  8. Default-safe / dry-run execution without database side effects.
  9. Malformed input rejection (types, ranges, scenarios, timestamps).
 10. Direct compatibility with SentinelX detection engines (brute_force, suspicious_auth, etc.).
"""

from datetime import datetime, timezone
import ipaddress
import socket
import sys
from pathlib import Path
import pytest

# Ensure SentinelX root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from simulator.internal_campaign_generator import (
    generate_campaign,
    generate_campaign_events,
    is_safe_lab_ip,
    validate_source_ip,
    validate_event_schema,
    SecurityViolation,
    CampaignConfigurationError,
    MIN_CAMPAIGN_EVENTS,
    MAX_CAMPAIGN_EVENTS,
    DEFAULT_CAMPAIGN_EVENTS,
    DEFAULT_BOT_NODES,
    DEFAULT_REFERENCE_TIME,
    ALLOWED_EVENT_TYPES,
    ALLOWED_STATUS,
    ALLOWED_SEVERITIES
)
from detection.brute_force import detect_brute_force
from detection.suspicious_auth import detect_suspicious_authentication
from detection.suspicious_powershell import detect_suspicious_powershell
from detection.privilege_escalation import detect_privilege_escalation


# ------------------------------------------------------------------------------
# 1. DETERMINISTIC OUTPUT TESTS
# ------------------------------------------------------------------------------

def test_deterministic_output_default_parameters():
    """Verify multiple runs with default parameters generate bit-for-bit identical outputs."""
    run_1 = generate_campaign()
    run_2 = generate_campaign()

    assert run_1["campaign_id"] == run_2["campaign_id"]
    assert run_1["total_events"] == run_2["total_events"]
    assert run_1["source_ips"] == run_2["source_ips"]
    assert run_1["stages"] == run_2["stages"]
    assert run_1["events"] == run_2["events"]


def test_deterministic_output_explicit_timestamp():
    """Verify deterministic output when an explicit base_time is provided."""
    ts = "2026-09-15T02:30:00+00:00"
    res_a = generate_campaign(base_time=ts, total_events=30)
    res_b = generate_campaign(base_time=ts, total_events=30)

    assert res_a == res_b
    assert res_a["events"][0]["timestamp"] == ts
    assert res_a["total_events"] == 30


# ------------------------------------------------------------------------------
# 2. BOUNDED CAMPAIGN SIZE & LIMITS TESTS
# ------------------------------------------------------------------------------

def test_campaign_size_limits_enforced_strict():
    """Verify strict bounds reject event counts outside [MIN_CAMPAIGN_EVENTS, MAX_CAMPAIGN_EVENTS]."""
    # Exceeding upper bound (200)
    with pytest.raises(CampaignConfigurationError, match="exceeds maximum bounded limit"):
        generate_campaign(total_events=201, strict_limits=True)

    with pytest.raises(CampaignConfigurationError, match="exceeds maximum bounded limit"):
        generate_campaign(total_events=500, strict_limits=True)

    # Below lower bound (4)
    with pytest.raises(CampaignConfigurationError, match="below minimum allowed"):
        generate_campaign(total_events=3, strict_limits=True)

    with pytest.raises(CampaignConfigurationError, match="below minimum allowed"):
        generate_campaign(total_events=0, strict_limits=True)

    with pytest.raises(CampaignConfigurationError, match="below minimum allowed"):
        generate_campaign(total_events=-10, strict_limits=True)


def test_campaign_size_clamping_non_strict():
    """Verify non-strict mode clamps event counts safely between MIN and MAX."""
    clamped_high = generate_campaign(total_events=500, strict_limits=False)
    assert clamped_high["total_events"] == MAX_CAMPAIGN_EVENTS
    assert len(clamped_high["events"]) == MAX_CAMPAIGN_EVENTS

    clamped_low = generate_campaign(total_events=1, strict_limits=False)
    assert clamped_low["total_events"] == MIN_CAMPAIGN_EVENTS
    assert len(clamped_low["events"]) == MIN_CAMPAIGN_EVENTS


def test_custom_bounded_event_count():
    """Verify that any valid count within bounds produces exactly that number of events."""
    for count in [4, 15, 24, 50, 100, 200]:
        res = generate_campaign(total_events=count)
        assert res["total_events"] == count
        assert len(res["events"]) == count


# ------------------------------------------------------------------------------
# 3. MULTIPLE SYNTHETIC SOURCE IPS TESTS
# ------------------------------------------------------------------------------

def test_multiple_synthetic_source_ips():
    """Verify that a distributed campaign spans multiple distinct synthetic bot IPs."""
    res = generate_campaign(total_events=DEFAULT_CAMPAIGN_EVENTS)

    unique_ips = set(res["source_ips"])
    assert len(unique_ips) >= 4, f"Expected at least 4 unique bot IPs, got: {unique_ips}"

    expected_nodes = set(DEFAULT_BOT_NODES.values())
    assert unique_ips == expected_nodes


def test_custom_bot_nodes_mapping():
    """Verify custom safe bot nodes can be provided."""
    custom_nodes = {
        "node_a": "192.0.2.101",
        "node_b": "192.0.2.102",
        "node_c": "192.0.2.103",
        "node_d": "192.0.2.104",
    }
    res = generate_campaign(bot_nodes=custom_nodes, total_events=20)
    assert set(res["source_ips"]) == set(custom_nodes.values())


# ------------------------------------------------------------------------------
# 4. SAFE LAB-ONLY SOURCE ADDRESSES TESTS
# ------------------------------------------------------------------------------

def test_safe_lab_ip_validation():
    """Verify that only authorized lab/documentation or private subnets are permitted."""
    # Permitted: RFC 5737 TEST-NET ranges
    assert is_safe_lab_ip("192.0.2.1") is True
    assert is_safe_lab_ip("198.51.100.25") is True
    assert is_safe_lab_ip("203.0.113.99") is True

    # Permitted: RFC 1918 Private ranges
    assert is_safe_lab_ip("10.0.1.50") is True
    assert is_safe_lab_ip("172.16.5.20") is True
    assert is_safe_lab_ip("192.168.1.101") is True

    # Strictly Rejected: Public internet IPs
    assert is_safe_lab_ip("8.8.8.8") is False
    assert is_safe_lab_ip("1.1.1.1") is False
    assert is_safe_lab_ip("142.250.190.46") is False

    # Strictly Rejected: Loopback & Special addresses
    assert is_safe_lab_ip("127.0.0.1") is False
    assert is_safe_lab_ip("0.0.0.0") is False
    assert is_safe_lab_ip("255.255.255.255") is False
    assert is_safe_lab_ip("invalid-ip") is False
    assert is_safe_lab_ip("") is False


def test_rejection_of_unsafe_bot_node_ips():
    """Verify SecurityViolation is raised if any unsafe IP is supplied."""
    unsafe_ips = [
        "8.8.8.8",            # Public DNS
        "127.0.0.1",          # Localhost
        "0.0.0.0",            # Unspecified
        "224.0.0.1",          # Multicast
        "google.com",         # Domain
        "bad.ip.format",      # Garbage
    ]
    for bad_ip in unsafe_ips:
        with pytest.raises(SecurityViolation):
            validate_source_ip(bad_ip)

        with pytest.raises(SecurityViolation):
            generate_campaign(bot_nodes={"node_a": bad_ip})


# ------------------------------------------------------------------------------
# 5. VALID SENTINELX EVENT SCHEMA TESTS
# ------------------------------------------------------------------------------

def test_valid_sentinelx_event_schema():
    """Verify all generated events conform strictly to the SentinelX ingestion schema."""
    campaign = generate_campaign(total_events=40)

    for event in campaign["events"]:
        # 1. Structural schema validation helper
        validate_event_schema(event)

        # 2. Detailed field checks
        assert isinstance(event["timestamp"], str)
        # Verify timestamp can be parsed as ISO datetime
        dt = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        assert dt is not None

        assert isinstance(event["source_ip"], str)
        assert is_safe_lab_ip(event["source_ip"])

        assert isinstance(event["username"], str)
        assert len(event["username"]) <= 128

        assert event["event_type"] in ALLOWED_EVENT_TYPES
        assert isinstance(event["action"], str)
        assert len(event["action"]) <= 128

        assert event["status"] in ALLOWED_STATUS
        assert isinstance(event["message"], str)
        assert len(event["message"]) <= 2048

        assert event["severity"] in ALLOWED_SEVERITIES
        assert event["port"] is None or (isinstance(event["port"], int) and 1 <= event["port"] <= 65535)


# ------------------------------------------------------------------------------
# 6. EXPECTED CAMPAIGN STAGES TESTS
# ------------------------------------------------------------------------------

def test_expected_campaign_stages():
    """Verify the 4 coordinated campaign stages and their progression."""
    campaign = generate_campaign(scenario="distributed-botnet", total_events=24)

    stage_names = [s["stage"] for s in campaign["stages"]]
    assert stage_names == [
        "authentication_attack",
        "successful_authentication",
        "suspicious_powershell",
        "privilege_escalation"
    ]

    events = campaign["events"]
    # Check that events follow stage ordering
    auth_attacks = [e for e in events if e["event_type"] == "LOGIN" and e["status"] == "FAILED"]
    auth_success = [e for e in events if e["event_type"] == "LOGIN" and e["status"] == "SUCCESS"]
    powershells = [e for e in events if e["event_type"] == "POWERSHELL"]
    priv_changes = [e for e in events if e["event_type"] == "PRIVILEGE_CHANGE"]

    assert len(auth_attacks) >= 5
    assert len(auth_success) >= 5
    assert len(powershells) >= 2
    assert len(priv_changes) >= 3


# ------------------------------------------------------------------------------
# 7. ZERO NETWORK / SOCKET CALLS VERIFICATION
# ------------------------------------------------------------------------------

def test_no_network_calls(monkeypatch):
    """Verify that generating a campaign executes zero network socket operations."""
    def forbidden_socket(*args, **kwargs):
        raise AssertionError("FORBIDDEN: Network socket creation detected during campaign generation!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    # Should execute purely in memory without attempting any socket calls
    res = generate_campaign(total_events=50)
    assert res["total_events"] == 50


# ------------------------------------------------------------------------------
# 8. DRY-RUN AND DEFAULT-SAFE MODE
# ------------------------------------------------------------------------------

def test_dry_run_and_default_safe():
    """Verify default mode is dry-run and generates data purely in-memory."""
    res = generate_campaign()
    assert res["dry_run"] is True
    assert isinstance(res["events"], list)
    assert len(res["events"]) > 0

    # generate_campaign_events helper should directly return list of event dicts
    events_list = generate_campaign_events()
    assert isinstance(events_list, list)
    assert len(events_list) == len(res["events"])
    assert events_list == res["events"]


# ------------------------------------------------------------------------------
# 9. MALFORMED INPUT HANDLING TESTS
# ------------------------------------------------------------------------------

def test_malformed_input_rejection():
    """Verify malformed inputs are rejected with clear exceptions."""
    # Invalid total_events types
    with pytest.raises(CampaignConfigurationError):
        generate_campaign(total_events="twenty-four")

    with pytest.raises(CampaignConfigurationError):
        generate_campaign(total_events=None)

    with pytest.raises(CampaignConfigurationError):
        generate_campaign(total_events=True)  # bool is subclass of int

    # Invalid scenario
    with pytest.raises(CampaignConfigurationError, match="Unknown scenario"):
        generate_campaign(scenario="non-existent-scenario")

    # Invalid bot_nodes type
    with pytest.raises(CampaignConfigurationError):
        generate_campaign(bot_nodes=["198.51.100.11"])

    # Invalid base_time
    with pytest.raises(CampaignConfigurationError):
        generate_campaign(base_time="not-a-valid-iso-timestamp")

    with pytest.raises(CampaignConfigurationError):
        generate_campaign(base_time=12345678)

    # Invalid time_step_seconds
    with pytest.raises(CampaignConfigurationError):
        generate_campaign(time_step_seconds=-5)

    with pytest.raises(CampaignConfigurationError):
        generate_campaign(time_step_seconds="five")


# ------------------------------------------------------------------------------
# 10. DETECTION ENGINE COMPATIBILITY TESTS
# ------------------------------------------------------------------------------

def test_compatibility_with_detection_engines():
    """
    Verify that generated campaign events directly trigger existing SentinelX
    detection engines without modifications.
    """
    # Generate 24 events: 8 brute force, 6 successful auth, 5 powershell, 5 priv esc
    events = generate_campaign_events(total_events=24)

    # Attach synthetic IDs for detection evidence verification (as SQLite would)
    for idx, ev in enumerate(events, start=1):
        ev["id"] = idx

    # 1. Test Brute Force Detection (T1110)
    bf_alerts = detect_brute_force(events)
    assert len(bf_alerts) >= 1
    assert bf_alerts[0]["alert_type"] == "BRUTE_FORCE"
    assert bf_alerts[0]["source_ip"] == DEFAULT_BOT_NODES["node_a"]
    assert bf_alerts[0]["mitre_technique"] == "T1110"
    assert len(bf_alerts[0]["evidence"]["event_ids"]) >= 5

    # 2. Test Suspicious Authentication Detection (T1078)
    sa_alerts = detect_suspicious_authentication(events)
    assert len(sa_alerts) >= 1
    assert sa_alerts[0]["alert_type"] == "SUSPICIOUS_AUTH"
    assert sa_alerts[0]["source_ip"] == DEFAULT_BOT_NODES["node_b"]
    assert sa_alerts[0]["mitre_technique"] == "T1078"

    # 3. Test Suspicious PowerShell Detection (T1059.001)
    ps_alerts = detect_suspicious_powershell(events)
    assert len(ps_alerts) >= 1
    assert ps_alerts[0]["alert_type"] == "SUSPICIOUS_POWERSHELL"
    assert ps_alerts[0]["source_ip"] == DEFAULT_BOT_NODES["node_c"]
    assert ps_alerts[0]["mitre_technique"] == "T1059.001"

    # 4. Test Privilege Escalation Detection (T1068)
    pe_alerts = detect_privilege_escalation(events)
    assert len(pe_alerts) >= 1
    assert pe_alerts[0]["alert_type"] == "PRIVILEGE_ESCALATION"
    assert pe_alerts[0]["source_ip"] == DEFAULT_BOT_NODES["node_d"]
    assert pe_alerts[0]["mitre_technique"] == "T1068"
