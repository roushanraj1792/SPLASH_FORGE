import sys
import os
import time
from datetime import datetime, timezone

# Add SentinelX project root to Python path
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database.database import insert_event
from services.ingestion_client import send_event


def submit_event(event):
    """
    Send event through SentinelX HTTP ingestion API
    when remote ingestion is configured.

    Otherwise, preserve local database behavior.
    """
    ingest_url = os.getenv(
        "SENTINELX_INGEST_URL",
        ""
    ).strip()

    if ingest_url:
        return send_event(event)

    return insert_event(event)


def generate_suspicious_powershell_events():

    attacker_ip = "192.168.1.90"

    suspicious_events = [
        {
            "action": "POWERSHELL",
            "message": (
                "PowerShell execution detected with "
                "ExecutionPolicy Bypass"
            )
        },
        {
            "action": "POWERSHELL",
            "message": (
                "PowerShell command detected with "
                "EncodedCommand"
            )
        }
    ]

    print("SPLASH FORGE Suspicious PowerShell Simulator")
    print("-----------------------------------------")

    event_ids = []

    for index, event in enumerate(
        suspicious_events,
        start=1
    ):

        event_data = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "source_ip": attacker_ip,

            "username": "demo_user",

            "event_type": "POWERSHELL",

            "action": event["action"],

            "status": "SUCCESS",

            "message": event["message"],

            "severity": "HIGH",

            "port": None
        }

        event_id = submit_event(event_data)
        event_ids.append(event_id)

        print(
            f"Suspicious PowerShell event "
            f"{index}/{len(suspicious_events)} "
            f"from {attacker_ip} "
            f"(event_id={event_id})"
        )

        time.sleep(0.3)

    print()
    print("Suspicious PowerShell simulation completed.")
    print(f"Source IP: {attacker_ip}")
    print(
        f"Generated events: "
        f"{len(suspicious_events)}"
    )
    return event_ids


if __name__ == "__main__":
    generate_suspicious_powershell_events()