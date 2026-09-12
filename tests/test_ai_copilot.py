from unittest.mock import patch

from services.ai_copilot import (
    extract_incident_iocs,
    build_incident_timeline,
    generate_rule_based_analysis,
    analyze_incident,
    normalize_record,
    normalize_events,
    extract_json_from_text,
)


def test_normalize_record_and_events():
    record = {"id": 1, "source_ip": "10.0.0.1"}
    normalized = normalize_record(record)
    assert normalized == record

    events = [record, {"id": 2, "source_ip": "10.0.0.2"}, None, "invalid"]
    norm_events = normalize_events(events)
    assert len(norm_events) == 2
    assert norm_events[0]["id"] == 1
    assert norm_events[1]["id"] == 2


def test_extract_incident_iocs():
    incident = {
        "incident_id": "INC-TEST-001",
        "source_ip": "192.168.1.50",
        "alert_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "risk_score": 85,
    }

    events = [
        {
            "id": 101,
            "timestamp": "2026-09-12T01:00:00Z",
            "source_ip": "192.168.1.50",
            "username": "admin",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "FAILED",
            "port": 22,
        },
        {
            "id": 102,
            "timestamp": "2026-09-12T01:00:15Z",
            "source_ip": "192.168.1.50",
            "username": "root",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "FAILED",
            "port": 22,
        },
    ]

    iocs = extract_incident_iocs(incident, events)

    assert iocs["source_ips"] == ["192.168.1.50"]
    assert "admin" in iocs["usernames"]
    assert "root" in iocs["usernames"]
    assert 22 in iocs["targeted_ports"]
    assert "LOGIN" in iocs["observed_event_types"]
    assert iocs["evidence_event_count"] == 2
    assert iocs["earliest_seen"] == "2026-09-12T01:00:00Z"
    assert iocs["latest_seen"] == "2026-09-12T01:00:15Z"


def test_build_incident_timeline():
    events = [
        {
            "id": 2,
            "timestamp": "2026-09-12T02:00:30Z",
            "source_ip": "10.10.10.5",
            "username": "victim_user",
            "event_type": "POWERSHELL",
            "action": "EXECUTION",
            "status": "SUCCESS",
            "message": "powershell.exe -enc AAAA",
        },
        {
            "id": 1,
            "timestamp": "2026-09-12T02:00:00Z",
            "source_ip": "10.10.10.5",
            "username": "victim_user",
            "event_type": "PORT_SCAN",
            "action": "SYN_SCAN",
            "status": "DETECTED",
            "message": "Port scan against range 20-80",
        },
    ]

    timeline = build_incident_timeline(events)

    assert len(timeline) == 2
    # Should be sorted chronologically ascending
    assert timeline[0]["event_type"] == "PORT_SCAN"
    assert timeline[0]["delta_str"] == "T+0s"
    assert "Reconnaissance" in timeline[0]["stage"]

    assert timeline[1]["event_type"] == "POWERSHELL"
    assert timeline[1]["delta_str"] == "T+30s"
    assert "Execution" in timeline[1]["stage"]


def test_generate_rule_based_analysis_structure():
    incident = {
        "incident_id": "INC-TEST-002",
        "source_ip": "172.16.0.4",
        "alert_type": "PORT_SCAN",
        "severity": "MEDIUM",
        "risk_score": 60,
        "mitre_technique": "T1046",
    }

    events = [
        {
            "id": 201,
            "timestamp": "2026-09-12T03:00:00Z",
            "source_ip": "172.16.0.4",
            "username": None,
            "event_type": "PORT_SCAN",
            "action": "SCAN",
            "status": "DETECTED",
            "port": 80,
            "message": "Probing port 80",
        }
    ]

    analysis = generate_rule_based_analysis(incident, events)

    # Core required keys
    assert "incident_summary" in analysis
    assert "severity_explanation" in analysis
    assert "mitre_explanation" in analysis
    assert "investigation_steps" in analysis
    assert "recommended_response" in analysis
    assert analysis["evidence_count"] == 1
    assert analysis["ai_source"] == "Rule-Based Fallback"

    # Core analyst workflow questions
    assert "what_happened" in analysis
    assert "why_suspicious" in analysis
    assert "verification_guidance" in analysis
    assert isinstance(analysis["verification_guidance"], list)

    # Forensic artifacts
    assert "iocs" in analysis
    assert "timeline" in analysis
    assert analysis["iocs"]["source_ips"] == ["172.16.0.4"]
    assert len(analysis["timeline"]) == 1


def test_analyze_incident_fallback_integration():
    incident = {
        "incident_id": "INC-TEST-003",
        "source_ip": "10.0.0.99",
        "alert_type": "SUSPICIOUS_AUTH",
        "severity": "HIGH",
        "risk_score": 75,
        "mitre_technique": "T1078",
    }

    events = [
        {
            "id": 301,
            "timestamp": "2026-09-12T04:00:00Z",
            "source_ip": "10.0.0.99",
            "username": "service_acct",
            "event_type": "LOGIN",
            "action": "AUTH",
            "status": "FAILED",
            "port": 3389,
            "message": "Auth failure outside business hours",
        }
    ]

    with patch("services.ai_copilot.generate_gemini_analysis", side_effect=RuntimeError("Simulated Gemini failure")):
        result = analyze_incident(incident, events)

    assert result is not None
    assert result.get("ai_source") == "Rule-Based Fallback"
    assert "Simulated Gemini failure" in result.get("ai_error", "")
    assert "incident_summary" in result
    assert "what_happened" in result
    assert "why_suspicious" in result
    assert "verification_guidance" in result
    assert "iocs" in result
    assert "timeline" in result
    assert len(result["timeline"]) == 1
    assert result["iocs"]["source_ips"] == ["10.0.0.99"]


def test_extract_json_from_text():
    # Pure JSON
    pure = '{"incident_summary": "Test", "count": 1}'
    res1 = extract_json_from_text(pure)
    assert res1["incident_summary"] == "Test"
    assert res1["count"] == 1

    # Markdown code fence
    fenced = '```json\n{"incident_summary": "Fenced"}\n```'
    res2 = extract_json_from_text(fenced)
    assert res2["incident_summary"] == "Fenced"

    # Pre-text and post-text around code fence
    mixed = 'Here is the analysis:\n```json\n{"incident_summary": "Mixed"}\n```\nHope this helps!'
    res3 = extract_json_from_text(mixed)
    assert res3["incident_summary"] == "Mixed"

    # Raw curly braces inside commentary without fence
    unfenced = 'Analyst Note: {"incident_summary": "Unfenced"} is ready.'
    res4 = extract_json_from_text(unfenced)
    assert res4["incident_summary"] == "Unfenced"


if __name__ == "__main__":
    test_normalize_record_and_events()
    test_extract_incident_iocs()
    test_build_incident_timeline()
    test_generate_rule_based_analysis_structure()
    test_analyze_incident_fallback_integration()
    test_extract_json_from_text()
    print("test_ai_copilot: ALL PASS")
