import os
import sys
from pathlib import Path

# Add SentinelX project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone
import time

from database.database import initialize_database, insert_event
from services.ingestion_client import send_event


# Initialize SentinelX database
initialize_database()


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


def simulate_suspicious_authentication():
    print("SentinelX Suspicious Authentication Simulator")
    print("--------------------------------------------")

    attacker_ip = "192.168.1.70"
    event_ids = []

    for attempt in range(1, 6):

        event = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "source_ip": attacker_ip,
            "username": "admin",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "SUCCESS",
            "message": f"Successful login event #{attempt}",
            "severity": "LOW",
            "port": None
        }

        event_id = submit_event(event)
        event_ids.append(event_id)

        print(
            f"Successful login #{attempt} "
            f"from {attacker_ip} "
            f"(event_id={event_id})"
        )

        time.sleep(0.3)

    print("\nSuspicious authentication simulation completed.")
    return event_ids


if __name__ == "__main__":
    simulate_suspicious_authentication()