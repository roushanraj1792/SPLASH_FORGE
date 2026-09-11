from datetime import datetime, timezone, timedelta

from detection.privilege_escalation import detect_privilege_escalation


def test_privilege_escalation_detection():
    base_time = datetime.now(timezone.utc)

    events = []

    for i in range(3):
        events.append({
            "id": i + 1,
            "timestamp": (base_time + timedelta(minutes=i)).isoformat(),
            "source_ip": "192.168.1.80",
            "username": "user1",
            "event_type": "PRIVILEGE_CHANGE",
            "action": "PRIVILEGE_GRANTED",
            "status": "SUCCESS",
            "message": "User privilege changed",
            "severity": "LOW",
        })

    alerts = detect_privilege_escalation(events)

    assert alerts, "Privilege-escalation alert was not generated"

    alert = alerts[0]

    assert alert["alert_type"] == "PRIVILEGE_ESCALATION"
    assert alert["source_ip"] == "192.168.1.80"
    assert alert["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert alert.get("mitre_technique")
