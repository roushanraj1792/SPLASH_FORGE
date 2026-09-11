import os
from typing import Any, Dict

import requests


INGEST_URL = os.getenv(
    "SENTINELX_INGEST_URL",
    ""
).strip()

INGEST_TOKEN = os.getenv(
    "SENTINELX_INGEST_TOKEN",
    ""
).strip()


def send_event(event: Dict[str, Any]) -> int:
    """
    Send a SentinelX security event.

    If SENTINELX_INGEST_URL is configured, the event is sent
    to the SentinelX ingestion API.

    Otherwise, the caller can use its existing local database
    insertion path.
    """

    if not INGEST_URL:
        raise RuntimeError(
            "SENTINELX_INGEST_URL is not configured."
        )

    if not INGEST_TOKEN:
        raise RuntimeError(
            "SENTINELX_INGEST_TOKEN is not configured."
        )

    headers = {
        "Authorization": f"Bearer {INGEST_TOKEN}",
        "Content-Type": "application/json",
    }

    response = requests.post(
        INGEST_URL,
        json=event,
        headers=headers,
        timeout=5,
    )

    response.raise_for_status()

    data = response.json()

    if not data.get("success"):
        raise RuntimeError(
            "SentinelX ingestion API rejected the event."
        )

    return int(data["event_id"])