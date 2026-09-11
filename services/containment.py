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
    "TERMINATE_SESSION",
    "NOTIFY_ADMIN",
}


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    return sqlite3.connect(DATABASE_PATH)


# ============================================================
# INITIALIZE CONTAINMENT TABLES
# ============================================================

def initialize_containment_tables():

    connection = get_connection()
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

    connection.close()

    return result is not None


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

    timestamp = datetime.now().isoformat(timespec="seconds")

    connection = get_connection()
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
# GET ACTIVE BLOCKED SOURCES
# ============================================================

def get_blocked_sources():

    initialize_containment_tables()

    connection = get_connection()
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