from datetime import datetime, timezone

from database.database import (
    initialize_database,
    insert_event,
    get_recent_events,
    create_incident,
    update_incident_status,
    get_incident_status_history,
)


def test_database_insert_and_retrieve():

    initialize_database()

    test_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "192.168.1.100",
        "username": "testuser",
        "event_type": "LOGIN",
        "action": "LOGIN_ATTEMPT",
        "status": "FAILED",
        "message": "Test failed login event",
        "severity": "LOW",
        "port": None,
    }

    event_id = insert_event(test_event)

    assert event_id is not None, "Event was not inserted"

    events = get_recent_events()

    assert events, "No events returned from database"

    latest = events[0]

    assert latest["id"] == event_id
    assert latest["source_ip"] == "192.168.1.100"
    assert latest["event_type"] == "LOGIN"
    assert latest["status"] == "FAILED"


def test_incident_status_transitions():
    initialize_database()

    alert = {
        "alert_type": "BRUTE_FORCE",
        "title": "Test Incident for Transitions",
        "source_ip": "10.42.42.42",
        "severity": "HIGH",
        "risk_score": 85,
        "mitre_technique": "T1110",
        "description": "Testing status lifecycle transitions",
    }

    incident_id = create_incident(alert)
    assert incident_id.startswith("INC-")

    # Initial status is NEW
    # Transition: NEW -> CONTAINED
    res1 = update_incident_status(incident_id, "CONTAINED")
    assert res1 == 1

    # Transition: CONTAINED -> INVESTIGATING (Revert containment/unblock)
    res2 = update_incident_status(incident_id, "INVESTIGATING")
    assert res2 == 1, "CONTAINED -> INVESTIGATING transition must succeed for containment reversal"

    # Transition: INVESTIGATING -> RESOLVED
    res3 = update_incident_status(incident_id, "RESOLVED")
    assert res3 == 1

    # Transition: RESOLVED -> INVESTIGATING (Reopen)
    res4 = update_incident_status(incident_id, "INVESTIGATING")
    assert res4 == 1, "RESOLVED -> INVESTIGATING transition must succeed for incident reopen"

    history = get_incident_status_history(incident_id)
    assert len(history) >= 4
