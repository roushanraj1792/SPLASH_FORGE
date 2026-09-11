import sqlite3
from datetime import datetime


# --------------------------------------------------
# DATABASE PATH
# --------------------------------------------------

DATABASE_PATH = "database/sentinelx.db"


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=15,
        check_same_thread=False
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA busy_timeout = 15000"
    )

    connection.execute(
        "PRAGMA journal_mode = WAL"
    )

    connection.execute(
        "PRAGMA synchronous = NORMAL"
    )

    return connection

# --------------------------------------------------
# INITIALIZE DATABASE
# --------------------------------------------------

def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    # --------------------------------------------------
    # SECURITY EVENTS TABLE
    # --------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT NOT NULL,

            source_ip TEXT,

            username TEXT,

            event_type TEXT,

            action TEXT,

            status TEXT,

            message TEXT,

            severity TEXT,

            port INTEGER

        )
        """
    )

    # --------------------------------------------------
    # INCIDENTS TABLE
    # --------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id TEXT UNIQUE,

            alert_type TEXT,

            title TEXT,

            source_ip TEXT,

            severity TEXT,

            risk_score INTEGER,

            mitre_technique TEXT,

            description TEXT,

            status TEXT DEFAULT 'NEW',

            created_at TEXT,

            updated_at TEXT

        )
        """
    )

    # --------------------------------------------------
    # INCIDENT EVENTS TABLE
    # --------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id TEXT,

            event_id INTEGER,

            linked_at TEXT

        )
        """
    )

    # --------------------------------------------------
    # INCIDENT STATUS HISTORY TABLE
    # --------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_status_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id TEXT NOT NULL,

            old_status TEXT,

            new_status TEXT NOT NULL,

            changed_at TEXT NOT NULL

        )
        """
    )

    connection.commit()

    connection.close()


# --------------------------------------------------
# INSERT SECURITY EVENT
# --------------------------------------------------

def insert_event(event):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO security_events (

            timestamp,
            source_ip,
            username,
            event_type,
            action,
            status,
            message,
            severity,
            port

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.get(
                "timestamp",
                datetime.now().isoformat()
            ),

            event.get(
                "source_ip",
                ""
            ),

            event.get(
                "username",
                ""
            ),

            event.get(
                "event_type",
                ""
            ),

            event.get(
                "action",
                ""
            ),

            event.get(
                "status",
                ""
            ),

            event.get(
                "message",
                ""
            ),

            event.get(
                "severity",
                "LOW"
            ),

            event.get(
                "port"
            )
        )
    )

    event_id = cursor.lastrowid

    connection.commit()

    connection.close()

    return event_id


# --------------------------------------------------
# GET RECENT EVENTS
# --------------------------------------------------

def get_recent_events(limit=100):

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            timestamp,
            source_ip,
            username,
            event_type,
            action,
            status,
            message,
            severity,
            port

        FROM security_events

        ORDER BY id DESC

        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


# --------------------------------------------------
# GET TOTAL SECURITY EVENT COUNT
# --------------------------------------------------

def get_total_event_count():

    connection = get_connection()

    row = connection.execute(
        """
        SELECT COUNT(*) AS count

        FROM security_events
        """
    ).fetchone()

    connection.close()

    return row["count"]


# --------------------------------------------------
# GET EVENTS BY SOURCE IP
# --------------------------------------------------

def get_events_by_source_ip(
    source_ip,
    limit=100
):

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            timestamp,
            source_ip,
            username,
            event_type,
            action,
            status,
            message,
            severity,
            port

        FROM security_events

        WHERE source_ip = ?

        ORDER BY id DESC

        LIMIT ?
        """,
        (
            source_ip,
            limit
        )
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


# --------------------------------------------------
# GET EVENTS BY SOURCE IP + TIME WINDOW
# --------------------------------------------------

def get_events_by_source_ip_time_window(
    source_ip,
    start_time,
    end_time,
    limit=100
):

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            timestamp,
            source_ip,
            username,
            event_type,
            action,
            status,
            message,
            severity,
            port

        FROM security_events

        WHERE source_ip = ?
          AND timestamp >= ?
          AND timestamp <= ?

        ORDER BY id ASC

        LIMIT ?
        """,
        (
            source_ip,
            start_time,
            end_time,
            limit
        )
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


# --------------------------------------------------
# CHECK INCIDENT EXISTS
# --------------------------------------------------

def incident_exists(
    alert_type,
    source_ip
):

    connection = get_connection()

    row = connection.execute(
        """
        SELECT incident_id

        FROM incidents

        WHERE alert_type = ?
        AND source_ip = ?

        LIMIT 1
        """,
        (
            alert_type,
            source_ip
        )
    ).fetchone()

    connection.close()

    return row is not None


# --------------------------------------------------
# CREATE INCIDENT
# --------------------------------------------------

def create_incident(alert):

    connection = get_connection()

    cursor = connection.cursor()

    # --------------------------------------------------
    # GENERATE INCIDENT ID
    # --------------------------------------------------

    row = cursor.execute(
        """
        SELECT MAX(
            CAST(
                SUBSTR(incident_id, 5)
                AS INTEGER
            )
        ) AS max_number

        FROM incidents
        """
    ).fetchone()

    max_number = row["max_number"] or 0

    incident_id = f"INC-{max_number + 1:04d}"

    now = datetime.now().isoformat()

    # --------------------------------------------------
    # DESCRIPTION
    # --------------------------------------------------

    description = (
        alert.get("description")
        or alert.get("message")
        or "Security incident detected."
    )

    # --------------------------------------------------
    # INSERT INCIDENT
    # --------------------------------------------------

    cursor.execute(
        """
        INSERT INTO incidents (

            incident_id,
            alert_type,
            title,
            source_ip,
            severity,
            risk_score,
            mitre_technique,
            description,
            status,
            created_at,
            updated_at

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident_id,

            alert.get(
                "alert_type",
                alert.get(
                    "type",
                    "UNKNOWN"
                )
            ),

            alert.get(
                "title",
                "Security Incident"
            ),

            alert.get(
                "source_ip",
                ""
            ),

            alert.get(
                "severity",
                "LOW"
            ),

            alert.get(
                "risk_score",
                0
            ),

            alert.get(
                "mitre_technique",
                "N/A"
            ),

            description,

            "NEW",

            now,

            now
        )
    )

    connection.commit()

    connection.close()

    return incident_id


# --------------------------------------------------
# GET INCIDENTS
# --------------------------------------------------

def get_incidents(limit=100):

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            incident_id,
            alert_type,
            title,
            source_ip,
            severity,
            risk_score,
            mitre_technique,
            description,
            status,
            created_at,
            updated_at

        FROM incidents

        ORDER BY id DESC

        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


# --------------------------------------------------
# GET ALL INCIDENTS
# --------------------------------------------------

def get_all_incidents():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            incident_id,
            alert_type,
            title,
            source_ip,
            severity,
            risk_score,
            mitre_technique,
            description,
            status,
            created_at,
            updated_at

        FROM incidents

        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    incidents = []

    for row in rows:

        incidents.append(
            {
                "incident_id": row["incident_id"],
                "alert_type": row["alert_type"],
                "title": row["title"],
                "source_ip": row["source_ip"],
                "severity": row["severity"],
                "risk_score": row["risk_score"],
                "mitre_technique": row["mitre_technique"],
                "description": row["description"],
                "status": row["status"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"]
            }
        )

    return incidents


# --------------------------------------------------
# LINK EVENT TO INCIDENT
# --------------------------------------------------

def link_event_to_incident(
    incident_id,
    event_id
):

    connection = get_connection()

    existing = connection.execute(
        """
        SELECT 1

        FROM incident_events

        WHERE incident_id = ?
          AND event_id = ?

        LIMIT 1
        """,
        (
            incident_id,
            event_id
        )
    ).fetchone()

    if existing:

        connection.close()

        return False

    connection.execute(
        """
        INSERT INTO incident_events (
            incident_id,
            event_id,
            linked_at
        )

        VALUES (?, ?, ?)
        """,
        (
            incident_id,
            event_id,
            datetime.now().isoformat()
        )
    )

    connection.commit()

    connection.close()

    return True


# --------------------------------------------------
# LINK MULTIPLE EVENTS TO INCIDENT
# --------------------------------------------------

def link_events_to_incident(
    incident_id,
    event_ids
):

    connection = get_connection()

    now = datetime.now().isoformat()

    for event_id in event_ids:

        existing = connection.execute(
            """
            SELECT 1

            FROM incident_events

            WHERE incident_id = ?
              AND event_id = ?

            LIMIT 1
            """,
            (
                incident_id,
                event_id
            )
        ).fetchone()

        if existing:

            continue

        connection.execute(
            """
            INSERT INTO incident_events (
                incident_id,
                event_id,
                linked_at
            )

            VALUES (?, ?, ?)
            """,
            (
                incident_id,
                event_id,
                now
            )
        )

    connection.commit()

    connection.close()


# --------------------------------------------------
# UNLINK EVENT FROM INCIDENT
# --------------------------------------------------

def unlink_event_from_incident(
    incident_id,
    event_id
):

    connection = get_connection()

    connection.execute(
        """
        DELETE FROM incident_events

        WHERE incident_id = ?
          AND event_id = ?
        """,
        (
            incident_id,
            event_id
        )
    )

    connection.commit()

    connection.close()


# --------------------------------------------------
# GET INCIDENT EVENTS
# --------------------------------------------------

def get_incident_events(
    incident_id
):

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            e.id,
            e.timestamp,
            e.source_ip,
            e.username,
            e.event_type,
            e.action,
            e.status,
            e.message,
            e.severity,
            e.port

        FROM security_events e

        INNER JOIN incident_events ie
            ON e.id = ie.event_id

        WHERE ie.incident_id = ?

        ORDER BY e.id ASC
        """,
        (incident_id,)
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


# --------------------------------------------------
# GET EVENT INCIDENTS
# --------------------------------------------------

def get_event_incidents(
    event_id
):

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            incident_id

        FROM incident_events

        WHERE event_id = ?
        """,
        (event_id,)
    ).fetchall()

    connection.close()

    return [
        row["incident_id"]
        for row in rows
    ]

# --------------------------------------------------
# GET INCIDENT EVENT COUNT
# --------------------------------------------------

def get_incident_event_count(
    incident_id
):

    connection = get_connection()

    row = connection.execute(
        """
        SELECT COUNT(*) AS event_count

        FROM incident_events

        WHERE incident_id = ?
        """,
        (
            incident_id,
        )
    ).fetchone()

    connection.close()

    return row["event_count"]
# --------------------------------------------------
# UPDATE INCIDENT STATUS
# --------------------------------------------------

def update_incident_status(
    incident_id,
    status
):

    allowed_transitions = {
        "NEW": ["TRIAGED", "CONTAINED"],
        "TRIAGED": ["INVESTIGATING"],
        "INVESTIGATING": ["CONTAINED"],
        "CONTAINED": ["RESOLVED"],
        "RESOLVED": []
    }

    connection = get_connection()

    cursor = connection.cursor()

    # --------------------------------------------------
    # GET CURRENT STATUS
    # --------------------------------------------------

    cursor.execute(
        """
        SELECT status

        FROM incidents

        WHERE incident_id = ?
        """,
        (incident_id,)
    )

    incident = cursor.fetchone()

    if incident is None:

        connection.close()

        return 0

    current_status = incident["status"]

    # --------------------------------------------------
    # VALIDATE STATUS TRANSITION
    # --------------------------------------------------

    if status not in allowed_transitions.get(
        current_status,
        []
    ):

        connection.close()

        return 0

    # --------------------------------------------------
    # UPDATE INCIDENT
    # --------------------------------------------------

    updated_at = datetime.now().isoformat()

    cursor.execute(
        """
        UPDATE incidents

        SET
            status = ?,
            updated_at = ?

        WHERE incident_id = ?
        """,
        (
            status,
            updated_at,
            incident_id
        )
    )

    updated_rows = cursor.rowcount

    # --------------------------------------------------
    # RECORD STATUS HISTORY
    # --------------------------------------------------

    if updated_rows == 1:

        cursor.execute(
            """
            INSERT INTO incident_status_history (
                incident_id,
                old_status,
                new_status,
                changed_at
            )

            VALUES (?, ?, ?, ?)
            """,
            (
                incident_id,
                current_status,
                status,
                updated_at
            )
        )

    connection.commit()

    connection.close()

    return updated_rows


# --------------------------------------------------
# GET INCIDENT STATUS HISTORY
# --------------------------------------------------

def get_incident_status_history(
    incident_id
):

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            incident_id,
            old_status,
            new_status,
            changed_at

        FROM incident_status_history

        WHERE incident_id = ?

        ORDER BY id ASC
        """,
        (incident_id,)
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]