from collections import defaultdict
from datetime import datetime, timedelta


PORT_SCAN_THRESHOLD = 10
TIME_WINDOW_MINUTES = 2


def detect_port_scan(events):
    """
    Detect multiple unique destination ports
    from the same source IP within a time window.

    The alert includes the exact event IDs that
    triggered the detection.
    """

    source_connections = defaultdict(list)
    alerts = []

    for event in events:
        if not isinstance(event, dict):
            continue

        if event.get("event_type") != "NETWORK_CONNECTION":
            continue

        source_ip = event.get("source_ip")
        if not source_ip:
            continue

        raw_ts = event.get("timestamp")
        if not raw_ts:
            continue

        try:
            event_time = datetime.fromisoformat(
                str(raw_ts).replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            continue

        port = event.get("port")
        if port is not None:
            try:
                port = int(port)
            except (ValueError, TypeError):
                port = str(port).strip()

        source_connections[source_ip].append({
            "id": event.get("id"),
            "timestamp": event_time,
            "port": port
        })

    for source_ip, connections in source_connections.items():

        connections.sort(
            key=lambda connection: connection["timestamp"]
        )

        for i in range(len(connections)):

            window_start = connections[i]["timestamp"]

            window_end = (
                window_start
                + timedelta(minutes=TIME_WINDOW_MINUTES)
            )

            window_connections = [
                connection
                for connection in connections[i:]
                if connection["timestamp"] <= window_end
            ]

            unique_ports = {
                connection["port"]
                for connection in window_connections
                if connection["port"] is not None
            }

            if len(unique_ports) >= PORT_SCAN_THRESHOLD:

                triggering_events = [
                    connection
                    for connection in window_connections
                    if connection["port"] is not None
                ]

                event_ids = [
                    connection["id"]
                    for connection in triggering_events
                ]

                alerts.append({
                    "alert_type": "PORT_SCAN",
                    "source_ip": source_ip,
                    "severity": "HIGH",
                    "mitre_technique": "T1046",
                    "title": "Port Scan Detected",
                    "message": (
                        f"{len(unique_ports)} different ports targeted "
                        f"by {source_ip} within "
                        f"{TIME_WINDOW_MINUTES} minutes."
                    ),
                    "evidence": {
                        "unique_ports": len(unique_ports),
                        "ports": sorted(unique_ports, key=lambda x: (isinstance(x, str), x)),
                        "source_ip": source_ip,
                        "event_ids": event_ids
                    }
                })

                break

    return alerts