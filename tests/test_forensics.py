import json
import pytest
from services.forensics import (
    extract_chain_of_custody,
    generate_forensic_dossier_json,
    generate_forensic_dossier_markdown,
)


def test_chain_of_custody_empty():
    res = extract_chain_of_custody([])
    assert res["total_events"] == 0
    assert res["earliest_timestamp"] is None
    assert res["latest_timestamp"] is None
    assert res["source_ips"] == []
    assert res["usernames"] == []


def test_chain_of_custody_populated():
    events = [
        {"timestamp": "2026-09-12T01:00:00Z", "source_ip": "10.0.0.5", "username": "alice", "port": 22, "event_type": "SSH"},
        {"timestamp": "2026-09-12T01:05:00Z", "source_ip": "10.0.0.5", "username": "bob", "port": 80, "event_type": "HTTP"},
        {"timestamp": "2026-09-12T01:02:00Z", "source_ip": "10.0.0.6", "username": "alice", "port": 22, "event_type": "SSH"},
    ]
    res = extract_chain_of_custody(events)
    assert res["total_events"] == 3
    assert res["earliest_timestamp"] == "2026-09-12T01:00:00Z"
    assert res["latest_timestamp"] == "2026-09-12T01:05:00Z"
    assert set(res["source_ips"]) == {"10.0.0.5", "10.0.0.6"}
    assert set(res["usernames"]) == {"alice", "bob"}
    assert set(res["targeted_ports"]) == {22, 80}
    assert set(res["event_types"]) == {"SSH", "HTTP"}


def test_generate_forensic_dossier_json():
    incident = {
        "incident_id": "INC-TEST-001",
        "title": "SSH Brute Force Attack",
        "severity": "HIGH",
        "status": "CONTAINED",
        "detection_type": "BRUTE_FORCE",
        "mitre_technique": "T1110",
        "source_ip": "192.168.1.100",
        "risk_score": 85,
        "created_at": "2026-09-12T01:00:00Z",
    }
    events = [
        {"timestamp": "2026-09-12T01:00:00Z", "source_ip": "192.168.1.100", "username": "root", "action": "LOGIN", "status": "FAILED", "message": "auth failed", "port": 22, "event_type": "LOGIN"},
    ]
    containment = [
        {"timestamp": "2026-09-12T01:02:00Z", "action": "BLOCK_SOURCE_IP", "source_ip": "192.168.1.100", "status": "SUCCESS", "reason": "Automated isolation"}
    ]
    history = [
        {"changed_at": "2026-09-12T01:02:00Z", "old_status": "INVESTIGATING", "new_status": "CONTAINED"}
    ]
    ai_rep = {
        "incident_summary": "Active brute force attempt from unauthorized host.",
        "ai_source": "Deterministic Heuristics Engine"
    }
    verification = {
        "is_verified": True,
        "status_message": "Zero post-containment packets observed.",
        "subsequent_events_count": 0
    }

    json_str = generate_forensic_dossier_json(incident, events, containment, history, ai_rep, verification)
    assert json_str is not None
    data = json.loads(json_str)
    assert data["incident_profile"]["incident_id"] == "INC-TEST-001"
    assert data["chain_of_custody"]["total_events"] == 1
    assert data["closed_loop_verification"]["is_verified"] is True
    assert len(data["containment_records"]) == 1
    assert len(data["workflow_audit_history"]) == 1


def test_generate_forensic_dossier_markdown():
    incident = {
        "incident_id": "INC-TEST-002",
        "title": "Port Scan Detected",
        "severity": "MEDIUM",
        "status": "INVESTIGATING",
        "detection_type": "PORT_SCAN",
        "mitre_technique": "T1046",
        "source_ip": "10.10.10.50",
        "risk_score": 60,
        "created_at": "2026-09-12T02:00:00Z",
    }
    events = [
        {"timestamp": "2026-09-12T02:00:00Z", "source_ip": "10.10.10.50", "username": None, "action": "CONNECT", "status": "BLOCKED", "message": "scan port 80", "port": 80, "event_type": "NETWORK"},
    ]

    md_str = generate_forensic_dossier_markdown(incident, events)
    assert "# 🛡️ SentinelX SOC Forensic Dossier: INC-TEST-002" in md_str
    assert "Port Scan Detected" in md_str
    assert "T1046" in md_str
    assert "10.10.10.50" in md_str
