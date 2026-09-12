from datetime import datetime, timezone, timedelta

from detection.brute_force import detect_brute_force


def test_brute_force_detection():
    now = datetime.now(timezone.utc)

    test_events = []

    for i in range(5):
        test_events.append({
            "id": i + 1,
            "timestamp": (now + timedelta(seconds=i * 20)).isoformat(),
            "source_ip": "192.168.1.50",
            "username": "admin",
            "event_type": "LOGIN",
            "action": "LOGIN_ATTEMPT",
            "status": "FAILED",
            "message": "Failed login attempt",
            "severity": "LOW",
        })

    alerts = detect_brute_force(test_events)

    assert alerts, "Brute-force alert was not generated"

    alert = alerts[0]

    assert alert["alert_type"] == "BRUTE_FORCE"
    assert alert["source_ip"] == "192.168.1.50"
    assert alert["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert alert.get("mitre_technique")


def test_brute_force_with_subsequent_isolated_attempt():
    now = datetime.now(timezone.utc) - timedelta(minutes=20)

    test_events = []
    # Cluster of 5 failed attempts
    for i in range(5):
        test_events.append({
            "id": i + 1,
            "timestamp": (now + timedelta(seconds=i * 10)).isoformat(),
            "source_ip": "10.0.0.99",
            "username": "root",
            "event_type": "LOGIN",
            "action": "LOGIN_ATTEMPT",
            "status": "FAILED",
            "message": "Failed login attempt",
            "severity": "LOW",
        })

    # Add single isolated failed login 10 minutes later
    test_events.append({
        "id": 99,
        "timestamp": (now + timedelta(minutes=10)).isoformat(),
        "source_ip": "10.0.0.99",
        "username": "root",
        "event_type": "LOGIN",
        "action": "LOGIN_ATTEMPT",
        "status": "FAILED",
        "message": "Single isolated failed attempt",
        "severity": "LOW",
    })

    alerts = detect_brute_force(test_events)
    assert len(alerts) == 1, "Failed to detect brute force when subsequent isolated event exists"
    assert alerts[0]["source_ip"] == "10.0.0.99"
    assert alerts[0]["evidence"]["failed_attempts"] == 5

