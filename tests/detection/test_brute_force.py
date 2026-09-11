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
