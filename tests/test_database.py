from datetime import datetime, timezone

from database.database import (
    initialize_database,
    insert_event,
    get_recent_events,
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
