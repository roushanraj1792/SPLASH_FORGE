import sqlite3
from datetime import datetime
from pathlib import Path


# --------------------------------------------------
# DATABASE PATH
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = str(BASE_DIR / "sentinelx.db")


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
    try:
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

        # --------------------------------------------------
        # PERFORMANCE INDEXES
        # --------------------------------------------------

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events (source_ip)"
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events (timestamp DESC)"
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events (event_type)"
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents (source_ip)"
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status)"
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_incident_events_lookup ON incident_events (incident_id, event_id)"
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_status_history_incident_id ON incident_status_history (incident_id)"
        )

        connection.commit()
    finally:
        connection.close()


# --------------------------------------------------
# INSERT SECURITY EVENT
# --------------------------------------------------

def insert_event(event):

    if not isinstance(event, dict):
        event = {}

    raw_ts = event.get("timestamp")
    timestamp = str(raw_ts).strip() if raw_ts is not None else ""
    if not timestamp:
        timestamp = datetime.now().isoformat()

    connection = get_connection()
    try:
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
                timestamp,

                event.get(
                    "source_ip",
                    ""
                ) or "",

                event.get(
                    "username",
                    ""
                ) or "",

                event.get(
                    "event_type",
                    ""
                ) or "",

                event.get(
                    "action",
                    ""
                ) or "",

                event.get(
                    "status",
                    ""
                ) or "",

                event.get(
                    "message",
                    ""
                ) or "",

                event.get(
                    "severity",
                    "LOW"
                ) or "LOW",

                event.get(
                    "port"
                )
            )
        )

        event_id = cursor.lastrowid

        connection.commit()

        return event_id
    finally:
        connection.close()


# --------------------------------------------------
# GET RECENT EVENTS
# --------------------------------------------------

def get_recent_events(limit=100):

    connection = get_connection()
    try:
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

        return [dict(row) for row in rows]
    finally:
        connection.close()


# --------------------------------------------------
# GET TOTAL SECURITY EVENT COUNT
# --------------------------------------------------

def get_total_event_count():

    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT COUNT(*) AS count

            FROM security_events
            """
        ).fetchone()

        return row["count"] if row else 0
    finally:
        connection.close()


# --------------------------------------------------
# GET EVENTS BY SOURCE IP
# --------------------------------------------------

def get_events_by_source_ip(
    source_ip,
    limit=100
):

    connection = get_connection()
    try:
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

        return [dict(row) for row in rows]
    finally:
        connection.close()


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
    try:
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

        return [dict(row) for row in rows]
    finally:
        connection.close()


# --------------------------------------------------
# CHECK INCIDENT EXISTS
# --------------------------------------------------

def incident_exists(
    alert_type,
    source_ip
):

    connection = get_connection()
    try:
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

        return row is not None
    finally:
        connection.close()


# --------------------------------------------------
# CREATE INCIDENT
# --------------------------------------------------

def create_incident(alert):

    if not alert or not isinstance(alert, dict):
        alert = {}

    connection = get_connection()
    try:
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

        max_number = (row["max_number"] if row else 0) or 0

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

        return incident_id
    finally:
        connection.close()


# --------------------------------------------------
# GET INCIDENTS
# --------------------------------------------------

def get_incidents(limit=100):

    connection = get_connection()
    try:
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

        return [dict(row) for row in rows]
    finally:
        connection.close()


# --------------------------------------------------
# GET ALL INCIDENTS
# --------------------------------------------------

def get_all_incidents():

    connection = get_connection()
    try:
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
    finally:
        connection.close()


# --------------------------------------------------
# LINK EVENT TO INCIDENT
# --------------------------------------------------

def link_event_to_incident(
    incident_id,
    event_id
):

    connection = get_connection()
    try:
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

        return True
    finally:
        connection.close()


# --------------------------------------------------
# LINK MULTIPLE EVENTS TO INCIDENT
# --------------------------------------------------

def link_events_to_incident(
    incident_id,
    event_ids
):

    connection = get_connection()
    try:
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
    finally:
        connection.close()


# --------------------------------------------------
# UNLINK EVENT FROM INCIDENT
# --------------------------------------------------

def unlink_event_from_incident(
    incident_id,
    event_id
):

    connection = get_connection()
    try:
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
    finally:
        connection.close()


# --------------------------------------------------
# GET INCIDENT EVENTS
# --------------------------------------------------

def get_incident_events(
    incident_id
):

    connection = get_connection()
    try:
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

        return [dict(row) for row in rows]
    finally:
        connection.close()


# --------------------------------------------------
# GET EVENT INCIDENTS
# --------------------------------------------------

def get_event_incidents(
    event_id
):

    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                incident_id

            FROM incident_events

            WHERE event_id = ?
            """,
            (event_id,)
        ).fetchall()

        return [
            row["incident_id"]
            for row in rows
        ]
    finally:
        connection.close()


# --------------------------------------------------
# GET INCIDENT EVENT COUNT
# --------------------------------------------------

def get_incident_event_count(
    incident_id
):

    connection = get_connection()
    try:
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

        return row["event_count"] if row else 0
    finally:
        connection.close()


# --------------------------------------------------
# UPDATE INCIDENT STATUS
# --------------------------------------------------

def update_incident_status(
    incident_id,
    status
):

    allowed_transitions = {
        "NEW": ["TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED"],
        "TRIAGED": ["INVESTIGATING", "CONTAINED", "RESOLVED", "NEW"],
        "INVESTIGATING": ["CONTAINED", "RESOLVED", "TRIAGED"],
        "CONTAINED": ["INVESTIGATING", "RESOLVED", "TRIAGED"],
        "RESOLVED": ["INVESTIGATING", "TRIAGED", "NEW"]
    }

    connection = get_connection()
    try:
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
            return 0

        current_status = incident["status"]

        # --------------------------------------------------
        # VALIDATE STATUS TRANSITION
        # --------------------------------------------------

        if status not in allowed_transitions.get(
            current_status,
            []
        ):
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

        return updated_rows
    finally:
        connection.close()


# --------------------------------------------------
# GET INCIDENT STATUS HISTORY
# --------------------------------------------------

def get_incident_status_history(
    incident_id
):

    connection = get_connection()
    try:
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

        return [dict(row) for row in rows]
    finally:
        connection.close()