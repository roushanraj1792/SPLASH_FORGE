from datetime import datetime, timezone, timedelta

from detection.suspicious_auth import detect_suspicious_authentication


def test_suspicious_authentication_detection():
    base_time = datetime.now(timezone.utc)

    events = []

    for i in range(5):
        events.append({
            "id": i + 1,
            "timestamp": (base_time + timedelta(minutes=i)).isoformat(),
            "source_ip": "192.168.1.70",
            "username": "admin",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "SUCCESS",
            "message": "Successful login",
            "severity": "LOW",
        })

    alerts = detect_suspicious_authentication(events)

    assert alerts, "Suspicious-authentication alert was not generated"

    alert = alerts[0]

    assert alert["alert_type"] == "SUSPICIOUS_AUTH"
    assert alert["source_ip"] == "192.168.1.70"
    assert alert["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert alert.get("mitre_technique")
