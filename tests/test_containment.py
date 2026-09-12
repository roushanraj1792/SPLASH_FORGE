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
    unblock_source_ip,
    is_source_blocked,
    get_source_containment_details,
    get_containment_actions,
    verify_source_containment,
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

    event_ids = alert["evidence"]["event_ids"]

    assert event_ids, "Detection alert evidence contains no event IDs"

    for event_id in event_ids:
        link_event_to_incident(
            incident_id,
            event_id
        )

    linked_events = get_incident_events(incident_id)

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

    # --------------------------------------------------
    # STEP 8: Verify active containment state & duplicate block
    # --------------------------------------------------

    assert is_source_blocked(SOURCE_IP) is True
    details = get_source_containment_details(SOURCE_IP)
    assert details is not None
    assert details.get("active") is True
    assert details.get("status") == "BLOCKED"

    # Duplicate block should return ALREADY_BLOCKED safely
    duplicate_res = block_source_ip(
        incident_id,
        SOURCE_IP,
        "Duplicate block check"
    )
    assert duplicate_res.get("status") == "ALREADY_BLOCKED"

    # --------------------------------------------------
    # STEP 9: Reversible containment (unblock)
    # --------------------------------------------------

    unblock_res = unblock_source_ip(
        incident_id,
        SOURCE_IP,
        "Analyst verified false-positive / remediation completed"
    )
    assert unblock_res.get("success") is True
    assert unblock_res.get("status") == "SUCCESS"
    assert is_source_blocked(SOURCE_IP) is False

    updated_details = get_source_containment_details(SOURCE_IP)
    assert updated_details is not None
    assert updated_details.get("active") is False
    assert updated_details.get("status") == "UNBLOCKED"

    # Attempting to unblock an already unblocked IP should fail safely
    unblock_again = unblock_source_ip(
        incident_id,
        SOURCE_IP,
        "Second unblock attempt"
    )
    assert unblock_again.get("success") is False
    assert unblock_again.get("status") == "NOT_BLOCKED"

    # --------------------------------------------------
    # STEP 10: Re-block after unblock (UPSERT verification)
    # --------------------------------------------------

    reblock_res = block_source_ip(
        incident_id,
        SOURCE_IP,
        "Re-blocking source after new threat detected"
    )
    assert reblock_res.get("success") is True
    assert reblock_res.get("status") == "SUCCESS"
    assert is_source_blocked(SOURCE_IP) is True

    # --------------------------------------------------
    # STEP 11: Closed-Loop Post-Containment Verification
    # --------------------------------------------------

    # With no subsequent events, containment is verified clean
    clean_verif = verify_source_containment(SOURCE_IP, events)
    assert clean_verif["is_contained"] is True
    assert clean_verif["is_verified"] is True
    assert clean_verif["subsequent_events_count"] == 0

    # With a simulated leak event occurring AFTER containment
    leak_event = {
        "timestamp": "2099-01-01T00:00:00Z",
        "source_ip": SOURCE_IP,
        "event_type": "LOGIN",
        "status": "FAILED"
    }
    leaked_verif = verify_source_containment(SOURCE_IP, [leak_event])
    assert leaked_verif["is_contained"] is True
    assert leaked_verif["is_verified"] is False
    assert leaked_verif["subsequent_events_count"] == 1


if __name__ == "__main__":
    test_containment_engine()
    print("test_containment_engine: PASS")

