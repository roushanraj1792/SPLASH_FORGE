from datetime import datetime, timezone, timedelta

from detection.port_scan import detect_port_scan


def test_port_scan_detection():
    now = datetime.now(timezone.utc)

    ports = [21, 22, 23, 25, 53, 80, 110, 135, 443, 445]

    test_events = []

    for i, port in enumerate(ports):
        test_events.append({
            "id": i + 1,
            "timestamp": (now + timedelta(seconds=i * 5)).isoformat(),
            "source_ip": "192.168.1.60",
            "username": None,
            "event_type": "NETWORK_CONNECTION",
            "action": "CONNECTION_ATTEMPT",
            "status": "FAILED",
            "message": f"Connection attempt to port {port}",
            "severity": "LOW",
            "port": port,
        })

    alerts = detect_port_scan(test_events)

    assert alerts, "Port-scan alert was not generated"

    alert = alerts[0]

    assert alert["alert_type"] == "PORT_SCAN"
    assert alert["source_ip"] == "192.168.1.60"
    assert alert["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert alert.get("mitre_technique")
