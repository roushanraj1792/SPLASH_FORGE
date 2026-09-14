from datetime import datetime, timezone
import os
import sys
import time
from pathlib import Path

# Add SentinelX project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from database.database import initialize_database, insert_event
from services.ingestion_client import send_event


SOURCE_IP = "192.168.1.80"
USERNAME = "attacker_sim"


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


def generate_privilege_escalation_events():
    initialize_database()

    print("SPLASH FORGE Privilege Escalation Simulator")
    print("---------------------------------------")

    event_ids = []

    for i in range(3):
        event = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "source_ip": SOURCE_IP,
            "username": USERNAME,
            "event_type": "PRIVILEGE_CHANGE",
            "action": "PRIVILEGE_ESCALATION",
            "status": "SUCCESS",
            "message": (
                f"Simulated privilege escalation attempt "
                f"{i + 1}/3 detected."
            ),
            "severity": "HIGH",
            "port": None
        }

        event_id = submit_event(event)
        event_ids.append(event_id)

        print(
            f"Privilege escalation event "
            f"{i + 1}/3 from {SOURCE_IP} "
            f"(event_id={event_id})"
        )

        time.sleep(0.3)

    print("\nPrivilege escalation simulation completed.")
    print(f"Source IP: {SOURCE_IP}")
    print("Generated events: 3")
    return event_ids


if __name__ == "__main__":
    generate_privilege_escalation_events()