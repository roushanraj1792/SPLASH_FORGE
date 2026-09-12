from collections import defaultdict
from datetime import datetime, timedelta

FAILED_ATTEMPT_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5


def detect_brute_force(events):
    """
    Detect multiple failed LOGIN attempts from the same source IP
    within a 5-minute window.

    The latest qualifying window is preferred so that newly
    ingested live events become the detection evidence.
    """

    failed_attempts = defaultdict(list)

    for event in events:
        if not isinstance(event, dict):
            continue

        if (
            event.get("event_type") != "LOGIN"
            or event.get("status") != "FAILED"
        ):
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

        failed_attempts[source_ip].append({
            "id": event.get("id"),
            "timestamp": event_time
        })

    alerts = []

    for source_ip, failed_events in failed_attempts.items():
        failed_events.sort(
            key=lambda item: item["timestamp"],
            reverse=True
        )

        for anchor_event in failed_events:
            window_end = anchor_event["timestamp"]
            window_start = window_end - timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            matching_events = [
                event
                for event in failed_events
                if window_start <= event["timestamp"] <= window_end
            ]

            if len(matching_events) >= FAILED_ATTEMPT_THRESHOLD:
                matching_events.sort(
                    key=lambda item: item["timestamp"]
                )

                event_ids = [
                    event["id"]
                    for event in matching_events
                ]

                alerts.append({
                    "alert_type": "BRUTE_FORCE",
                    "source_ip": source_ip,
                    "severity": "HIGH",
                    "mitre_technique": "T1110",
                    "title": "Brute Force Attack Detected",
                    "message": (
                        f"{len(matching_events)} failed login attempts "
                        f"detected from {source_ip} "
                        f"within {TIME_WINDOW_MINUTES} minutes."
                    ),
                    "evidence": {
                        "failed_attempts": len(matching_events),
                        "source_ip": source_ip,
                        "event_ids": event_ids
                    }
                })
                break

    return alerts
