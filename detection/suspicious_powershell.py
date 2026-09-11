from collections import defaultdict
from datetime import datetime, timedelta


TIME_WINDOW_MINUTES = 10
EVENT_THRESHOLD = 2


SUSPICIOUS_PATTERNS = [
    "encodedcommand",
    "-enc ",
    "downloadstring",
    "invoke-expression",
    "iex ",
    "bypass",
    "hidden",
    "executionpolicy bypass"
]


def detect_suspicious_powershell(events):

    suspicious_events = defaultdict(list)
    alerts = []

    for event in events:

        if event["event_type"] != "POWERSHELL":
            continue

        source_ip = event["source_ip"]
        message = (event["message"] or "").lower()

        matched_pattern = None

        for pattern in SUSPICIOUS_PATTERNS:

            if pattern in message:
                matched_pattern = pattern
                break

        if matched_pattern is None:
            continue

        try:
            event_time = datetime.fromisoformat(
                event["timestamp"].replace("Z", "+00:00")
            )
        except ValueError:
            continue

        suspicious_events[source_ip].append(
            {
                "id": event["id"],
                "timestamp": event_time,
                "pattern": matched_pattern
            }
        )

    for source_ip, event_data in suspicious_events.items():

        event_data.sort(
            key=lambda item: item["timestamp"]
        )

        for i in range(len(event_data)):

            window_start = event_data[i]["timestamp"]

            window_end = (
                window_start
                + timedelta(minutes=TIME_WINDOW_MINUTES)
            )

            matching_events = [
                item
                for item in event_data[i:]
                if item["timestamp"] <= window_end
            ]

            if len(matching_events) >= EVENT_THRESHOLD:

                patterns = sorted(
                    set(
                        item["pattern"]
                        for item in matching_events
                    )
                )

                event_ids = [
                    item["id"]
                    for item in matching_events
                ]

                alerts.append(
                    {
                        "alert_type": "SUSPICIOUS_POWERSHELL",

                        "source_ip": source_ip,

                        "severity": "HIGH",

                        "mitre_technique": "T1059.001",

                        "title": "Suspicious PowerShell Detected",

                        "message": (
                            f"{len(matching_events)} suspicious "
                            f"PowerShell events detected from "
                            f"{source_ip} within "
                            f"{TIME_WINDOW_MINUTES} minutes. "
                            f"Patterns: {', '.join(patterns)}."
                        ),

                        "evidence": {
                            "event_count": len(matching_events),
                            "source_ip": source_ip,
                            "patterns": patterns,
                            "event_ids": event_ids
                        }
                    }
                )

                break

    return alerts