"""
Edge case and malformed telemetry testing for SentinelX detection engines.
Verifies that engines handle None, missing keys, invalid timestamps,
and non-dict elements gracefully without raising exceptions.
"""

from detection.brute_force import detect_brute_force
from detection.port_scan import detect_port_scan
from detection.privilege_escalation import detect_privilege_escalation
from detection.suspicious_auth import detect_suspicious_authentication
from detection.suspicious_powershell import detect_suspicious_powershell


def test_detection_engines_empty_input():
    assert detect_brute_force([]) == []
    assert detect_port_scan([]) == []
    assert detect_privilege_escalation([]) == []
    assert detect_suspicious_authentication([]) == []
    assert detect_suspicious_powershell([]) == []


def test_detection_engines_malformed_records():
    malformed_events = [
        None,
        "not a dict",
        {},
        {"event_type": None},
        {"event_type": "LOGIN", "status": None},
        {"event_type": "LOGIN", "status": "FAILED", "source_ip": None},
        {"event_type": "LOGIN", "status": "FAILED", "source_ip": "1.2.3.4", "timestamp": "invalid-ts"},
        {"event_type": "NETWORK_CONNECTION", "source_ip": "1.2.3.4", "timestamp": None, "port": None},
        {"event_type": "PRIVILEGE_CHANGE", "status": "SUCCESS", "source_ip": None},
        {"event_type": "POWERSHELL", "message": None, "source_ip": None},
    ]

    # None of these should raise an exception
    assert detect_brute_force(malformed_events) == []
    assert detect_port_scan(malformed_events) == []
    assert detect_privilege_escalation(malformed_events) == []
    assert detect_suspicious_authentication(malformed_events) == []
    assert detect_suspicious_powershell(malformed_events) == []


def test_port_scan_mixed_port_types():
    from datetime import datetime, timedelta
    now = datetime.now()
    events = []
    # Create 10 events with mixed int and str ports
    for i in range(10):
        events.append({
            "id": i + 1,
            "event_type": "NETWORK_CONNECTION",
            "source_ip": "192.168.10.10",
            "timestamp": (now + timedelta(seconds=i * 5)).isoformat(),
            "port": str(8000 + i) if i % 2 == 0 else (8000 + i)
        })
    alerts = detect_port_scan(events)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "PORT_SCAN"
    assert alerts[0]["evidence"]["unique_ports"] == 10


if __name__ == "__main__":
    test_detection_engines_empty_input()
    test_detection_engines_malformed_records()
    test_port_scan_mixed_port_types()
    print("test_detection_edge_cases: ALL PASS")
