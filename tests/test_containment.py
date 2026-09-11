from datetime import datetime, timedelta, timezone
import random

from database.database import (
    insert_event,
    create_incident,
    link_event_to_incident,
    get_incident_events,
)

from detection.brute_force import detect_brute_force
from services.risk_engine import enrich_alert_with_risk
from services.containment import (
    initialize_containment_tables,
    block_source_ip,
    get_containment_actions,
)


def test_containment_engine():

    # Unique private IP for every test run
    SOURCE_IP = (
        f"10.253.{random.randint(1, 254)}."
        f"{random.randint(1, 254)}"
    )

    initialize_containment_tables()

    # --------------------------------------------------
    # STEP 1: Create controlled brute-force events
    # --------------------------------------------------

    events = []

    for i in range(5):

        event_time = (
            datetime.now() - timedelta(minutes=4 - i)
        ).isoformat()

        event = {
            "timestamp": event_time,
            "source_ip": SOURCE_IP,
            "username": "demo_user",
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "FAILED",
            "message": "Controlled SentinelX brute-force simulation",
            "severity": "HIGH",
            "port": None,
        }

        event_id = insert_event(event)

        event["id"] = event_id
        events.append(event)

    # --------------------------------------------------
    # STEP 2: Brute-force detection
    # --------------------------------------------------

    alerts = detect_brute_force(events)

    assert alerts, "Brute-force detection generated no alerts"

    alert = alerts[0]

    assert alert.get("alert_type") == "BRUTE_FORCE"

    # --------------------------------------------------
    # STEP 3: Risk enrichment
    # --------------------------------------------------

    alert = enrich_alert_with_risk(alert)

    assert alert.get("risk_score") is not None
    assert alert.get("risk_level") in [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]

    # --------------------------------------------------
    # STEP 4: Create incident
    # --------------------------------------------------

    incident_id = create_incident(alert)

    assert incident_id, "Incident was not created"

    # --------------------------------------------------
    # STEP 5: Link evidence
    # --------------------------------------------------

    event_ids = alert.get("event_ids", [])

    for event_id in event_ids:
        link_event_to_incident(
            incident_id,
            event_id
        )

    linked_events = get_incident_events(incident_id)

    # Evidence linking is checked only when detector
    # provides event IDs.
    if event_ids:
        assert linked_events, "Detection evidence was not linked"

    # --------------------------------------------------
    # STEP 6: Execute containment
    # --------------------------------------------------

    reason = (
        "Automated containment test for "
        "controlled brute-force attack"
    )

    containment_result = block_source_ip(
        incident_id,
        SOURCE_IP,
        reason
    )

    assert containment_result.get("success") is True

    assert containment_result.get("status") == "SUCCESS", (
        f"Expected SUCCESS but got: "
        f"{containment_result.get('status')}"
    )

    # --------------------------------------------------
    # STEP 7: Verify containment audit
    # --------------------------------------------------

    actions = get_containment_actions()

    incident_actions = [
        action
        for action in actions
        if action.get("incident_id") == incident_id
    ]

    assert incident_actions, (
        "No containment audit record created"
    )

    latest_action = incident_actions[0]

    assert latest_action.get("action") == "BLOCK_SOURCE_IP"

    assert latest_action.get("status") == "SUCCESS"

    assert latest_action.get("source_ip") == SOURCE_IP
