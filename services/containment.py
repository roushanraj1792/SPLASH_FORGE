import sqlite3
from datetime import datetime
from pathlib import Path


# ============================================================
# SENTINELX SAFE CONTAINMENT / POLICY ENGINE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database" / "sentinelx.db"


# ============================================================
# ALLOWED DEFENSIVE ACTIONS
# ============================================================

ALLOWED_ACTIONS = {
    "BLOCK_SOURCE_IP",
    "UNBLOCK_SOURCE_IP",
    "TERMINATE_SESSION",
    "NOTIFY_ADMIN",
}


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=15,
        check_same_thread=False
    )
    connection.execute("PRAGMA busy_timeout = 15000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


# ============================================================
# INITIALIZE CONTAINMENT TABLES
# ============================================================

def initialize_containment_tables():

    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS containment_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                action TEXT NOT NULL,
                source_ip TEXT,
                status TEXT NOT NULL,
                reason TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT UNIQUE NOT NULL,
                incident_id TEXT NOT NULL,
                reason TEXT,
                blocked_at TEXT NOT NULL,
                active INTEGER DEFAULT 1
            )
            """
        )

        connection.commit()
    finally:
        connection.close()


# ============================================================
# POLICY CHECK
# ============================================================

def is_action_allowed(action):

    return action in ALLOWED_ACTIONS


# ============================================================
# CHECK WHETHER SOURCE IP IS ALREADY BLOCKED
# ============================================================

def is_source_blocked(source_ip):

    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT 1
            FROM blocked_sources
            WHERE source_ip = ?
            AND active = 1
            LIMIT 1
            """,
            (source_ip,)
        )

        result = cursor.fetchone()

        return result is not None
    finally:
        connection.close()


# ============================================================
# BLOCK SOURCE IP
# ============================================================

def block_source_ip(incident_id, source_ip, reason):

    initialize_containment_tables()

    # --------------------------------------------------------
    # Validate source IP
    # --------------------------------------------------------

    if not source_ip:

        return {
            "success": False,
            "action": "BLOCK_SOURCE_IP",
            "message": "Source IP is missing."
        }

    # --------------------------------------------------------
    # Policy validation
    # --------------------------------------------------------

    if not is_action_allowed("BLOCK_SOURCE_IP"):

        return {
            "success": False,
            "action": "BLOCK_SOURCE_IP",
            "message": "Containment action is not allowed."
        }

    # --------------------------------------------------------
    # Prevent duplicate blocking
    # --------------------------------------------------------

    if is_source_blocked(source_ip):

        return {
            "success": True,
            "action": "BLOCK_SOURCE_IP",
            "source_ip": source_ip,
            "status": "ALREADY_BLOCKED",
            "message": f"{source_ip} is already blocked."
        }

    # --------------------------------------------------------
    # Create timestamp
    # --------------------------------------------------------

    timestamp = datetime.now().isoformat()

    connection = get_connection()
    try:
        cursor = connection.cursor()

        # --------------------------------------------------------
        # Add source IP to controlled SentinelX blocklist
        # --------------------------------------------------------

        cursor.execute(
            """
            INSERT INTO blocked_sources (
                source_ip,
                incident_id,
                reason,
                blocked_at,
                active
            )
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(source_ip) DO UPDATE SET
                incident_id = excluded.incident_id,
                reason = excluded.reason,
                blocked_at = excluded.blocked_at,
                active = 1
            """,
            (
                source_ip,
                incident_id,
                reason,
                timestamp
            )
        )

        # --------------------------------------------------------
        # Create containment audit record
        # --------------------------------------------------------

        cursor.execute(
            """
            INSERT INTO containment_actions (
                incident_id,
                action,
                source_ip,
                status,
                reason,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                "BLOCK_SOURCE_IP",
                source_ip,
                "SUCCESS",
                reason,
                timestamp
            )
        )

        connection.commit()
    finally:
        connection.close()

    # --------------------------------------------------------
    # Return result
    # --------------------------------------------------------

    return {
        "success": True,
        "action": "BLOCK_SOURCE_IP",
        "source_ip": source_ip,
        "status": "SUCCESS",
        "message": (
            f"Source IP {source_ip} was safely added "
            "to the SentinelX blocklist."
        ),
        "timestamp": timestamp
    }


# ============================================================
# UNBLOCK SOURCE IP (REVERSIBLE CONTAINMENT)
# ============================================================

def unblock_source_ip(incident_id, source_ip, reason="Analyst remediation / verification completed"):
    """
    Safely unblock a contained source IP.
    Ensures containment is reversible, auditable, and traceable.
    """

    initialize_containment_tables()

    if not source_ip:
        return {
            "success": False,
            "action": "UNBLOCK_SOURCE_IP",
            "message": "Source IP is missing."
        }

    if not is_action_allowed("UNBLOCK_SOURCE_IP"):
        return {
            "success": False,
            "action": "UNBLOCK_SOURCE_IP",
            "message": "Containment action is not allowed."
        }

    if not is_source_blocked(source_ip):
        return {
            "success": False,
            "action": "UNBLOCK_SOURCE_IP",
            "source_ip": source_ip,
            "status": "NOT_BLOCKED",
            "message": f"{source_ip} is not currently blocked."
        }

    timestamp = datetime.now().isoformat()

    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE blocked_sources
            SET active = 0
            WHERE source_ip = ?
            """,
            (source_ip,)
        )

        cursor.execute(
            """
            INSERT INTO containment_actions (
                incident_id,
                action,
                source_ip,
                status,
                reason,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                "UNBLOCK_SOURCE_IP",
                source_ip,
                "SUCCESS",
                reason,
                timestamp
            )
        )

        connection.commit()
    finally:
        connection.close()

    return {
        "success": True,
        "action": "UNBLOCK_SOURCE_IP",
        "source_ip": source_ip,
        "status": "SUCCESS",
        "message": (
            f"Source IP {source_ip} was safely removed "
            "from the SentinelX blocklist."
        ),
        "timestamp": timestamp
    }


# ============================================================
# GET SOURCE CONTAINMENT DETAILS
# ============================================================

def get_source_containment_details(source_ip):
    """
    Query containment record and active status for a specific source IP.
    """

    initialize_containment_tables()

    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                source_ip,
                incident_id,
                reason,
                blocked_at,
                active
            FROM blocked_sources
            WHERE source_ip = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (source_ip,)
        )

        row = cursor.fetchone()
    finally:
        connection.close()

    if not row:
        return None

    return {
        "id": row[0],
        "source_ip": row[1],
        "incident_id": row[2],
        "reason": row[3],
        "blocked_at": row[4],
        "active": row[5] == 1,
        "status": "BLOCKED" if row[5] == 1 else "UNBLOCKED"
    }


# ============================================================
# GET ACTIVE BLOCKED SOURCES
# ============================================================

def get_blocked_sources():

    initialize_containment_tables()

    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                source_ip,
                incident_id,
                reason,
                blocked_at,
                active
            FROM blocked_sources
            WHERE active = 1
            ORDER BY id DESC
            """
        )

        rows = cursor.fetchall()
    finally:
        connection.close()

    results = []

    for row in rows:

        results.append(
            {
                "id": row[0],
                "source_ip": row[1],
                "incident_id": row[2],
                "reason": row[3],
                "blocked_at": row[4],
                "status": "BLOCKED" if row[5] == 1 else "INACTIVE"
            }
        )

    return results


# ============================================================
# GET CONTAINMENT AUDIT LOG
# ============================================================

def get_containment_actions():

    initialize_containment_tables()

    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                incident_id,
                action,
                source_ip,
                status,
                reason,
                timestamp
            FROM containment_actions
            ORDER BY id DESC
            """
        )

        rows = cursor.fetchall()
    finally:
        connection.close()

    results = []

    for row in rows:

        results.append(
            {
                "id": row[0],
                "incident_id": row[1],
                "action": row[2],
                "source_ip": row[3],
                "status": row[4],
                "reason": row[5],
                "timestamp": row[6]
            }
        )

    return results


# ============================================================
# VERIFY SOURCE CONTAINMENT (CLOSED-LOOP VERIFICATION)
# ============================================================

def _parse_timestamp(ts_str):
    if not ts_str:
        return None
    try:
        clean = str(ts_str).replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return None


def verify_source_containment(source_ip, events=None):
    """
    Verify whether a quarantined source IP has generated any subsequent
    telemetry events since containment was applied.
    Enforces closed-loop verification:
    DECISION -> EVIDENCE -> EXPLANATION -> RESPONSE -> VERIFICATION
    """

    details = get_source_containment_details(source_ip)

    if not details or not details.get("active"):
        return {
            "is_contained": False,
            "is_verified": False,
            "blocked_at": None,
            "subsequent_events_count": 0,
            "status_message": "Host is not currently isolated in the containment registry."
        }

    blocked_at = str(details.get("blocked_at") or "")
    blocked_dt = _parse_timestamp(blocked_at)
    subsequent_count = 0

    if events and blocked_dt:
        for ev in events:
            if not isinstance(ev, dict):
                continue
            if ev.get("source_ip") == source_ip:
                raw_ts = ev.get("timestamp")
                ev_dt = _parse_timestamp(raw_ts)
                if ev_dt:
                    cmp_ev = ev_dt
                    cmp_block = blocked_dt
                    # If one is timezone-aware and the other is naive, harmonize to naive
                    if cmp_ev.tzinfo is not None and cmp_block.tzinfo is None:
                        cmp_ev = cmp_ev.replace(tzinfo=None)
                    elif cmp_ev.tzinfo is None and cmp_block.tzinfo is not None:
                        cmp_block = cmp_block.replace(tzinfo=None)

                    if cmp_ev > cmp_block:
                        subsequent_count += 1

    if subsequent_count == 0:
        return {
            "is_contained": True,
            "is_verified": True,
            "blocked_at": blocked_at,
            "subsequent_events_count": 0,
            "status_message": "Zero post-containment telemetry packets observed. Threat neutralized."
        }
    else:
        return {
            "is_contained": True,
            "is_verified": False,
            "blocked_at": blocked_at,
            "subsequent_events_count": subsequent_count,
            "status_message": f"Containment leak: {subsequent_count} subsequent event(s) observed after isolation timestamp!"
        }