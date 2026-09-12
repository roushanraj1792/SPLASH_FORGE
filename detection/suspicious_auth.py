from datetime import datetime, timedelta

ALERT_TYPE = "SUSPICIOUS_AUTH"
MITRE_TECHNIQUE = "T1078"
SEVERITY = "MEDIUM"
RISK_SCORE = 45

THRESHOLD = 5
TIME_WINDOW_MINUTES = 10


def detect_suspicious_authentication(events):
    alerts = []

    login_events = [
        event
        for event in events
        if isinstance(event, dict)
        and str(event.get("event_type", "")).upper() == "LOGIN"
        and str(event.get("action", "")).upper() == "LOGIN"
        and str(event.get("status", "")).upper() == "SUCCESS"
    ]

    events_by_ip = {}

    for event in login_events:
        source_ip = event.get("source_ip")

        if not source_ip:
            continue

        events_by_ip.setdefault(source_ip, []).append(event)

    for source_ip, ip_events in events_by_ip.items():

        ip_events.sort(
            key=lambda event: str(event.get("timestamp", ""))
        )

        for i in range(len(ip_events)):

            try:
                start_time = datetime.fromisoformat(
                    str(ip_events[i].get("timestamp", "")).replace("Z", "+00:00")
                )
            except (ValueError, TypeError, KeyError):
                continue

            window_events = []

            for event in ip_events[i:]:

                try:
                    event_time = datetime.fromisoformat(
                        str(event.get("timestamp", "")).replace("Z", "+00:00")
                    )
                except (ValueError, TypeError, KeyError):
                    continue

                if event_time - start_time <= timedelta(
                    minutes=TIME_WINDOW_MINUTES
                ):
                    window_events.append(event)
                else:
                    break

            if len(window_events) >= THRESHOLD:

                selected_events = window_events[:THRESHOLD]

                event_ids = [
                    event.get("id")
                    for event in selected_events
                    if event.get("id") is not None
                ]

                usernames = sorted(
                    {
                        str(event.get("username"))
                        for event in selected_events
                        if event.get("username")
                    }
                )

                description = (
                    f"{THRESHOLD} successful authentication events "
                    f"detected from {source_ip} within "
                    f"{TIME_WINDOW_MINUTES} minutes."
                )

                alerts.append(
                    {
                        "alert_type": ALERT_TYPE,
                        "title": "Suspicious Authentication Detected",
                        "source_ip": source_ip,
                        "severity": SEVERITY,
                        "risk_score": RISK_SCORE,
                        "mitre_technique": MITRE_TECHNIQUE,
                        "description": description,
                        "message": description,
                        "evidence": {
                            "event_ids": event_ids,
                            "usernames": usernames,
                        },
                    }
                )

                break

    return alerts
