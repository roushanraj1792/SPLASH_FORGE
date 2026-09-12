from datetime import datetime, timedelta
from collections import defaultdict


TIME_WINDOW_MINUTES = 10
EVENT_THRESHOLD = 3


def detect_privilege_escalation(events):

    suspicious_events = defaultdict(list)
    alerts = []

    for event in events:
        if not isinstance(event, dict):
            continue

        if event.get("event_type") != "PRIVILEGE_CHANGE":
            continue

        if event.get("status") != "SUCCESS":
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

        suspicious_events[source_ip].append(
            {
                "id": event.get("id"),
                "timestamp": event_time,
                "event": event
            }
        )

    for source_ip, records in suspicious_events.items():

        records.sort(
            key=lambda record: record["timestamp"]
        )

        for i in range(len(records)):

            window_start = records[i]["timestamp"]

            window_end = (
                window_start
                + timedelta(minutes=TIME_WINDOW_MINUTES)
            )

            window_records = [
                record
                for record in records[i:]
                if record["timestamp"] <= window_end
            ]

            event_count = len(window_records)

            if event_count >= EVENT_THRESHOLD:

                event_ids = [
                    record["id"]
                    for record in window_records
                ]

                alerts.append(
                    {
                        "alert_type": "PRIVILEGE_ESCALATION",

                        "source_ip": source_ip,

                        "severity": "HIGH",

                        "mitre_technique": "T1068",

                        "title": "Privilege Escalation Detected",

                        "message": (
                            f"{event_count} suspicious privilege "
                            f"change events detected from "
                            f"{source_ip} within "
                            f"{TIME_WINDOW_MINUTES} minutes."
                        ),

                        "evidence": {
                            "event_count": event_count,
                            "source_ip": source_ip,
                            "event_ids": event_ids
                        }
                    }
                )

                break

    return alerts