from datetime import datetime, timezone, timedelta

from detection.suspicious_powershell import detect_suspicious_powershell


def test_suspicious_powershell_detection():
    base_time = datetime.now(timezone.utc)

    messages = [
        "powershell.exe -EncodedCommand ABC123",
        "powershell.exe -ExecutionPolicy Bypass -Hidden",
    ]

    events = []

    for i, message in enumerate(messages):
        events.append({
            "id": i + 1,
            "timestamp": (base_time + timedelta(minutes=i)).isoformat(),
            "source_ip": "192.168.1.90",
            "username": "admin",
            "event_type": "POWERSHELL",
            "action": "PROCESS_START",
            "status": "SUCCESS",
            "message": message,
            "severity": "LOW",
        })

    alerts = detect_suspicious_powershell(events)

    assert alerts, "Suspicious-PowerShell alert was not generated"

    alert = alerts[0]

    assert alert["alert_type"] == "SUSPICIOUS_POWERSHELL"
    assert alert["source_ip"] == "192.168.1.90"
    assert alert["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert alert.get("mitre_technique")
