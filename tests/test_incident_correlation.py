from datetime import datetime, timezone

from database.database import (
    initialize_database,
    insert_event,
    create_incident,
    link_events_to_incident,
    get_incident_events,
    get_incident_event_count,
)


def test_incident_event_correlation():
    initialize_database()

    events = []

    for i in range(3):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.168.1.200",
            "username": "test_user",
            "event_type": "LOGIN",
            "action": "LOGIN_ATTEMPT",
            "status": "FAILED",
            "message": f"Test failed login event {i + 1}",
            "severity": "HIGH",
            "port": None,
        }

        event_id = insert_event(event)

        assert event_id is not None, (
            f"Event {i + 1} was not inserted"
        )

        events.append(event_id)

    assert len(events) == 3

    alert = {
        "alert_type": "BRUTE_FORCE",
        "title": "Incident Correlation Test",
        "source_ip": "192.168.1.200",
        "severity": "HIGH",
        "risk_score": 70,
        "mitre_technique": "T1110",
        "description": "Test incident for event correlation.",
    }

    incident_id = create_incident(alert)

    assert incident_id is not None, "Incident was not created"

    link_events_to_incident(
        incident_id,
        events,
    )

    linked_events = get_incident_events(incident_id)
    event_count = get_incident_event_count(incident_id)

    assert linked_events, "No events were linked to the incident"
    assert len(linked_events) == 3
    assert event_count == 3
