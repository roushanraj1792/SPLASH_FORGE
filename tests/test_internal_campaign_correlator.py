"""
Unit & Integration Tests for Internal Campaign Correlator
=========================================================
Tests:
  1. Deterministic correlation (identical events yield identical campaign outputs).
  2. Single-stage campaigns (single source and distributed multi-source).
  3. Multi-stage campaigns (full attack progression: Auth -> Compromise -> PowerShell -> PrivEsc).
  4. Multiple synthetic source IP handling (distributed botnet correlation).
  5. Chronological event ordering and tie-breaking.
  6. Campaign identity generation and structure.
  7. Stage classification and MITRE technique mapping.
  8. Malformed input rejection (types, missing fields, invalid IP, invalid status/types).
  9. Collection size limits enforcement (MAX_EVENTS_BOUND).
 10. Temporal window clustering across time gaps.
 11. Zero network or socket activity verification.
 12. Zero database side effects verification.
 13. End-to-end integration with simulator/internal_campaign_generator.py.
"""

from datetime import datetime, timedelta, timezone
import ipaddress
import socket
import sys
from pathlib import Path
import pytest

# Ensure SentinelX root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from simulator.internal_campaign_correlator import (
    correlate_campaigns,
    correlate_single_campaign,
    classify_event_stage,
    validate_events_collection,
    validate_event_dict,
    parse_iso_timestamp,
    CampaignCorrelationError,
    MAX_EVENTS_BOUND,
    DEFAULT_CORRELATION_WINDOW_MINUTES,
    STAGE_DEFINITIONS
)
from simulator.internal_campaign_generator import (
    generate_campaign,
    generate_campaign_events,
    DEFAULT_BOT_NODES
)
from database.database import get_recent_events, get_incidents


# ------------------------------------------------------------------------------
# 1. DETERMINISTIC CORRELATION TESTS
# ------------------------------------------------------------------------------

def test_deterministic_correlation():
    """Verify that multiple correlation runs on the same events yield identical outputs."""
    raw_events = generate_campaign_events(total_events=24)

    run_1 = correlate_campaigns(raw_events)
    run_2 = correlate_campaigns(raw_events)

    assert len(run_1) == len(run_2) == 1
    c1, c2 = run_1[0], run_2[0]

    assert c1["campaign_id"] == c2["campaign_id"]
    assert c1["campaign_name"] == c2["campaign_name"]
    assert c1["correlation_type"] == c2["correlation_type"]
    assert c1["event_count"] == c2["event_count"]
    assert c1["stage_count"] == c2["stage_count"]
    assert c1["sources"] == c2["sources"]
    assert c1["techniques"] == c2["techniques"]
    assert c1["ordered_stages"] == c2["ordered_stages"]
    assert c1["first_observed"] == c2["first_observed"]
    assert c1["last_observed"] == c2["last_observed"]
    assert c1["correlation_reason"] == c2["correlation_reason"]


def test_correlate_single_campaign_helper():
    """Verify correlate_single_campaign returns the dominant campaign."""
    events = generate_campaign_events(total_events=20)
    campaign = correlate_single_campaign(events)

    assert campaign is not None
    assert campaign["event_count"] == 20
    assert campaign["stage_count"] == 4


def test_empty_events_collection():
    """Verify empty collection returns empty list or None for single campaign."""
    assert correlate_campaigns([]) == []
    assert correlate_single_campaign([]) is None


# ------------------------------------------------------------------------------
# 2. SINGLE-STAGE CAMPAIGN TESTS
# ------------------------------------------------------------------------------

def test_single_stage_focused_campaign():
    """Verify single-stage campaign with a single source is classified as SINGLE_STAGE_FOCUSED."""
    events = [
        {
            "id": i,
            "timestamp": f"2026-09-15T01:00:{i:02d}+00:00",
            "source_ip": "198.51.100.11",
            "username": "admin",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "FAILED",
            "message": f"Failed login #{i}",
            "severity": "LOW",
            "port": None,
        }
        for i in range(1, 6)
    ]

    campaigns = correlate_campaigns(events)
    assert len(campaigns) == 1
    c = campaigns[0]

    assert c["correlation_type"] == "SINGLE_STAGE_FOCUSED"
    assert c["stage_count"] == 1
    assert c["event_count"] == 5
    assert c["sources"] == ["198.51.100.11"]
    assert c["techniques"] == ["T1110"]
    assert c["ordered_stages"][0]["stage_key"] == "authentication_attack"
    assert c["ordered_stages"][0]["event_ids"] == [1, 2, 3, 4, 5]


def test_single_stage_distributed_campaign():
    """Verify single-stage attack from multiple sources is classified as SINGLE_STAGE_DISTRIBUTED."""
    events = [
        {
            "timestamp": "2026-09-15T01:00:05+00:00",
            "source_ip": "198.51.100.11",
            "username": "admin",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "FAILED",
            "message": "Auth failure 1",
            "severity": "LOW",
            "port": None,
        },
        {
            "timestamp": "2026-09-15T01:00:10+00:00",
            "source_ip": "198.51.100.12",
            "username": "admin",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "FAILED",
            "message": "Auth failure 2",
            "severity": "LOW",
            "port": None,
        },
        {
            "timestamp": "2026-09-15T01:00:15+00:00",
            "source_ip": "198.51.100.13",
            "username": "admin",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "FAILED",
            "message": "Auth failure 3",
            "severity": "LOW",
            "port": None,
        },
    ]

    campaigns = correlate_campaigns(events)
    assert len(campaigns) == 1
    c = campaigns[0]

    assert c["correlation_type"] == "SINGLE_STAGE_DISTRIBUTED"
    assert c["stage_count"] == 1
    assert len(c["sources"]) == 3
    assert c["techniques"] == ["T1110"]


# ------------------------------------------------------------------------------
# 3. MULTI-STAGE CAMPAIGN TESTS
# ------------------------------------------------------------------------------

def test_multi_stage_distributed_campaign():
    """Verify full 4-stage distributed campaign is correlated into MULTI_STAGE_DISTRIBUTED."""
    raw_events = generate_campaign_events(total_events=24)
    # Add synthetic IDs to verify event_ids tracking
    for i, ev in enumerate(raw_events, start=101):
        ev["id"] = i

    campaigns = correlate_campaigns(raw_events)
    assert len(campaigns) == 1
    c = campaigns[0]

    assert c["correlation_type"] == "MULTI_STAGE_DISTRIBUTED"
    assert c["stage_count"] == 4
    assert c["event_count"] == 24
    assert len(c["sources"]) == 4

    # Verify expected stage progression order
    stages = c["ordered_stages"]
    assert stages[0]["stage_key"] == "authentication_attack"
    assert stages[0]["mitre_technique"] == "T1110"
    assert stages[0]["sources"] == [DEFAULT_BOT_NODES["node_a"]]

    assert stages[1]["stage_key"] == "successful_authentication"
    assert stages[1]["mitre_technique"] == "T1078"
    assert stages[1]["sources"] == [DEFAULT_BOT_NODES["node_b"]]

    assert stages[2]["stage_key"] == "suspicious_powershell"
    assert stages[2]["mitre_technique"] == "T1059.001"
    assert stages[2]["sources"] == [DEFAULT_BOT_NODES["node_c"]]

    assert stages[3]["stage_key"] == "privilege_escalation"
    assert stages[3]["mitre_technique"] == "T1068"
    assert stages[3]["sources"] == [DEFAULT_BOT_NODES["node_d"]]

    # Verify techniques aggregate
    assert set(c["techniques"]) == {"T1110", "T1078", "T1059.001", "T1068"}

    # Verify event ID preservation across stages
    all_stage_event_ids = []
    for s in stages:
        all_stage_event_ids.extend(s["event_ids"])
    assert len(all_stage_event_ids) == 24
    assert all_stage_event_ids == list(range(101, 125))


def test_multi_stage_focused_single_source():
    """Verify multi-stage attack from single IP is classified as MULTI_STAGE_FOCUSED."""
    single_ip = "192.168.1.50"
    events = [
        # Stage 1: Brute force
        {
            "timestamp": "2026-09-15T01:00:00+00:00",
            "source_ip": single_ip,
            "username": "root",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "FAILED",
            "message": "Failed login",
            "severity": "LOW",
            "port": None,
        },
        # Stage 2: Successful login
        {
            "timestamp": "2026-09-15T01:01:00+00:00",
            "source_ip": single_ip,
            "username": "root",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "SUCCESS",
            "message": "Successful login",
            "severity": "LOW",
            "port": None,
        },
        # Stage 3: PowerShell
        {
            "timestamp": "2026-09-15T01:02:00+00:00",
            "source_ip": single_ip,
            "username": "root",
            "event_type": "POWERSHELL",
            "action": "POWERSHELL",
            "status": "SUCCESS",
            "message": "PowerShell ExecutionPolicy Bypass",
            "severity": "HIGH",
            "port": None,
        },
    ]

    campaigns = correlate_campaigns(events)
    assert len(campaigns) == 1
    c = campaigns[0]

    assert c["correlation_type"] == "MULTI_STAGE_FOCUSED"
    assert c["stage_count"] == 3
    assert c["sources"] == [single_ip]


# ------------------------------------------------------------------------------
# 4. CHRONOLOGICAL EVENT ORDERING & TIE-BREAKING
# ------------------------------------------------------------------------------

def test_events_sorted_chronologically():
    """Verify correlator accepts events out of chronological order and sorts them."""
    events = [
        {
            "id": 3,
            "timestamp": "2026-09-15T01:05:00+00:00",
            "source_ip": "198.51.100.11",
            "event_type": "POWERSHELL",
            "action": "POWERSHELL",
            "status": "SUCCESS",
            "message": "PowerShell cmd",
            "severity": "HIGH",
        },
        {
            "id": 1,
            "timestamp": "2026-09-15T01:00:00+00:00",
            "source_ip": "198.51.100.11",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "FAILED",
            "message": "Login failed",
            "severity": "LOW",
        },
        {
            "id": 2,
            "timestamp": "2026-09-15T01:02:30+00:00",
            "source_ip": "198.51.100.11",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "SUCCESS",
            "message": "Login ok",
            "severity": "LOW",
        },
    ]

    campaigns = correlate_campaigns(events)
    assert len(campaigns) == 1
    c = campaigns[0]

    assert c["first_observed"] == "2026-09-15T01:00:00+00:00"
    assert c["last_observed"] == "2026-09-15T01:05:00+00:00"
    assert c["duration_seconds"] == 300.0


# ------------------------------------------------------------------------------
# 5. TEMPORAL WINDOW & MULTIPLE CAMPAIGNS TESTS
# ------------------------------------------------------------------------------

def test_temporal_window_splitting():
    """Verify events separated by more than time_window_minutes form separate campaigns."""
    t1 = "2026-09-15T01:00:00+00:00"
    t2 = "2026-09-15T01:05:00+00:00"
    # Gap of 2 hours (> 30 min window)
    t3 = "2026-09-15T03:00:00+00:00"
    t4 = "2026-09-15T03:05:00+00:00"

    events = [
        {"timestamp": t1, "source_ip": "198.51.100.11", "event_type": "LOGIN", "status": "FAILED"},
        {"timestamp": t2, "source_ip": "198.51.100.11", "event_type": "LOGIN", "status": "FAILED"},
        {"timestamp": t3, "source_ip": "198.51.100.12", "event_type": "POWERSHELL", "status": "SUCCESS"},
        {"timestamp": t4, "source_ip": "198.51.100.12", "event_type": "POWERSHELL", "status": "SUCCESS"},
    ]

    campaigns = correlate_campaigns(events, time_window_minutes=30.0)
    assert len(campaigns) == 2

    assert campaigns[0]["first_observed"] == t1
    assert campaigns[0]["last_observed"] == t2
    assert campaigns[0]["sources"] == ["198.51.100.11"]

    assert campaigns[1]["first_observed"] == t3
    assert campaigns[1]["last_observed"] == t4
    assert campaigns[1]["sources"] == ["198.51.100.12"]


def test_custom_campaign_id_prefix():
    """Verify custom campaign ID prefix is applied correctly."""
    events = [
        {"timestamp": "2026-09-15T01:00:00+00:00", "source_ip": "198.51.100.11", "event_type": "LOGIN", "status": "FAILED"}
    ]
    campaigns = correlate_campaigns(events, campaign_id_prefix="INC-CAMPAIGN")
    assert len(campaigns) == 1
    assert campaigns[0]["campaign_id"] == "INC-CAMPAIGN-001"


# ------------------------------------------------------------------------------
# 6. STAGE CLASSIFICATION TESTS
# ------------------------------------------------------------------------------

def test_classify_event_stage_all_types():
    """Verify classify_event_stage correctly maps all supported event types."""
    # Failed Login -> authentication_attack
    c1 = classify_event_stage({"event_type": "LOGIN", "status": "FAILED"})
    assert c1["stage_key"] == "authentication_attack"
    assert c1["mitre_technique"] == "T1110"

    # Successful Login -> successful_authentication
    c2 = classify_event_stage({"event_type": "LOGIN", "status": "SUCCESS"})
    assert c2["stage_key"] == "successful_authentication"
    assert c2["mitre_technique"] == "T1078"

    # PowerShell -> suspicious_powershell
    c3 = classify_event_stage({"event_type": "POWERSHELL", "status": "SUCCESS"})
    assert c3["stage_key"] == "suspicious_powershell"
    assert c3["mitre_technique"] == "T1059.001"

    # Privilege change -> privilege_escalation
    c4 = classify_event_stage({"event_type": "PRIVILEGE_CHANGE", "status": "SUCCESS"})
    assert c4["stage_key"] == "privilege_escalation"
    assert c4["mitre_technique"] == "T1068"

    # Network connection -> reconnaissance
    c5 = classify_event_stage({"event_type": "NETWORK_CONNECTION", "status": "FAILED"})
    assert c5["stage_key"] == "reconnaissance"
    assert c5["mitre_technique"] == "T1046"


# ------------------------------------------------------------------------------
# 7. MALFORMED INPUT REJECTION TESTS
# ------------------------------------------------------------------------------

def test_rejection_of_non_collection():
    """Verify non-collection inputs are rejected."""
    with pytest.raises(CampaignCorrelationError, match="cannot be None"):
        correlate_campaigns(None)

    with pytest.raises(CampaignCorrelationError, match="must be a list or tuple"):
        correlate_campaigns("not-a-list")

    with pytest.raises(CampaignCorrelationError, match="must be a list or tuple"):
        correlate_campaigns(12345)


def test_rejection_of_malformed_event_items():
    """Verify invalid event elements raise CampaignCorrelationError."""
    # Element is not a dict
    with pytest.raises(CampaignCorrelationError, match="must be a dictionary"):
        correlate_campaigns(["not-a-dict"])

    # Missing required field
    with pytest.raises(CampaignCorrelationError, match="missing required field"):
        correlate_campaigns([{"source_ip": "198.51.100.11", "event_type": "LOGIN"}])

    # Invalid timestamp
    with pytest.raises(CampaignCorrelationError, match="Failed to parse timestamp"):
        correlate_campaigns([{
            "timestamp": "invalid-timestamp",
            "source_ip": "198.51.100.11",
            "event_type": "LOGIN",
            "status": "FAILED"
        }])

    # Invalid IP address
    with pytest.raises(CampaignCorrelationError, match="Malformed IPv4 address"):
        correlate_campaigns([{
            "timestamp": "2026-09-15T01:00:00+00:00",
            "source_ip": "999.999.999.999",
            "event_type": "LOGIN",
            "status": "FAILED"
        }])

    # Unsupported event type
    with pytest.raises(CampaignCorrelationError, match="unsupported event_type"):
        correlate_campaigns([{
            "timestamp": "2026-09-15T01:00:00+00:00",
            "source_ip": "198.51.100.11",
            "event_type": "MALWARE_DOWNLOAD",
            "status": "FAILED"
        }])

    # Unsupported status
    with pytest.raises(CampaignCorrelationError, match="unsupported status"):
        correlate_campaigns([{
            "timestamp": "2026-09-15T01:00:00+00:00",
            "source_ip": "198.51.100.11",
            "event_type": "LOGIN",
            "status": "PENDING"
        }])


# ------------------------------------------------------------------------------
# 8. BOUNDED COLLECTION SIZE LIMITS
# ------------------------------------------------------------------------------

def test_collection_size_limit_enforced():
    """Verify collections exceeding MAX_EVENTS_BOUND are rejected."""
    # Create valid minimal event
    single_event = {
        "timestamp": "2026-09-15T01:00:00+00:00",
        "source_ip": "198.51.100.11",
        "event_type": "LOGIN",
        "status": "FAILED"
    }
    oversized = [single_event] * (MAX_EVENTS_BOUND + 1)

    with pytest.raises(CampaignCorrelationError, match="exceeds maximum bounded limit"):
        correlate_campaigns(oversized)


# ------------------------------------------------------------------------------
# 9. ZERO NETWORK / SOCKET CALLS VERIFICATION
# ------------------------------------------------------------------------------

def test_no_network_or_socket_calls(monkeypatch):
    """Verify that correlating events makes zero network socket operations."""
    def forbidden_socket(*args, **kwargs):
        raise AssertionError("FORBIDDEN: Network socket call detected in correlator!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    events = generate_campaign_events(total_events=30)
    campaigns = correlate_campaigns(events)
    assert len(campaigns) == 1


# ------------------------------------------------------------------------------
# 10. ZERO DATABASE SIDE EFFECTS VERIFICATION
# ------------------------------------------------------------------------------

def test_no_database_modifications():
    """Verify that running correlation does not insert new events or incidents into database."""
    events_before = len(get_recent_events(limit=100))
    incidents_before = len(get_incidents())

    raw_events = generate_campaign_events(total_events=20)
    campaigns = correlate_campaigns(raw_events)
    assert len(campaigns) == 1

    events_after = len(get_recent_events(limit=100))
    incidents_after = len(get_incidents())

    assert events_before == events_after, "Database security_events changed during correlation!"
    assert incidents_before == incidents_after, "Database incidents changed during correlation!"
