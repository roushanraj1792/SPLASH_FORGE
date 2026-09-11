import sys
from pathlib import Path

# Add SentinelX project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone
import os
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


def simulate_port_scan():
    print("SentinelX Port Scan Attack Simulator")
    print("------------------------------------")

    attacker_ip = "192.168.1.61"

    ports = [
        21, 22, 23, 25, 53,
        80, 110, 135, 443, 445
    ]

    for port in ports:

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": attacker_ip,
            "username": None,
            "event_type": "NETWORK_CONNECTION",
            "action": "CONNECTION_ATTEMPT",
            "status": "FAILED",
            "message": f"Connection attempt to port {port}",
            "severity": "LOW",
            "port": port
        }

        event_id = submit_event(event)

        print(
            f"Connection attempt from "
            f"{attacker_ip} to port {port} "
            f"(event_id={event_id})"
        )

        time.sleep(0.5)

    print("\nPort-scan simulation completed.")


if __name__ == "__main__":
    simulate_port_scan()