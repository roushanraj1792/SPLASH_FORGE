"""
SentinelX — Enterprise Authentication & Role-Based Access Control (RBAC)
PBKDF2-HMAC-SHA256 password hashing with constant-time verification.
Provides multi-user session management and privilege separation for SOC teams.
"""

import hashlib
import os
import secrets
from datetime import datetime
from pathlib import Path
import sqlite3

from database.database import get_connection, DATABASE_PATH


ROLES = {"ADMIN", "ANALYST", "AUDITOR"}


def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with 100,000 iterations.
    Returns (hex_hash, hex_salt).
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100_000
    )
    return hashed.hex(), salt.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """
    Verify a plaintext password against a stored salt and hash using constant-time comparison.
    """
    try:
        salt = bytes.fromhex(salt_hex)
        expected_hash, _ = hash_password(password, salt=salt)
        return secrets.compare_digest(expected_hash, hash_hex)
    except Exception:
        return False


def init_auth_table():
    """
    Initialize users table and seed initial demo accounts if empty.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'ANALYST',
                created_at TEXT NOT NULL,
                last_login TEXT
            )
            """
        )
        conn.commit()

        # Check if users table is empty; if so, seed default demo accounts
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]

        if count == 0:
            now = datetime.now().isoformat()
            
            # Seed Demo Admin
            admin_hash, admin_salt = hash_password("SentinelX@Admin2026")
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                ("admin", admin_hash, admin_salt, "ADMIN", now)
            )

            # Seed Demo SOC Analyst
            analyst_hash, analyst_salt = hash_password("SentinelX@Analyst2026")
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                ("analyst", analyst_hash, analyst_salt, "ANALYST", now)
            )

            conn.commit()
    finally:
        conn.close()


def authenticate_user(username: str, password: str):
    """
    Authenticate a user by username and password.
    Returns user dict without sensitive hashes, or None if authentication fails.
    """
    init_auth_table()

    if not username or not password:
        return None

    clean_user = str(username).strip().lower()

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, password_hash, salt, role, created_at, last_login
            FROM users
            WHERE lower(username) = ?
            LIMIT 1
            """,
            (clean_user,)
        )
        row = cursor.fetchone()

        if not row:
            return None

        user_id = row[0]
        uname = row[1]
        stored_hash = row[2]
        stored_salt = row[3]
        role = row[4]
        created_at = row[5]

        if not verify_password(password, stored_salt, stored_hash):
            return None

        # Update last_login timestamp
        now = datetime.now().isoformat()
        cursor.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (now, user_id)
        )
        conn.commit()

        return {
            "id": user_id,
            "username": uname,
            "role": role,
            "created_at": created_at,
            "last_login": now
        }
    finally:
        conn.close()


def create_user(username: str, password: str, role: str = "ANALYST") -> tuple[bool, str]:
    """
    Register a new user account with hashed credentials.
    """
    init_auth_table()

    clean_user = str(username or "").strip().lower()
    clean_role = str(role or "ANALYST").strip().upper()

    if len(clean_user) < 3:
        return False, "Username must be at least 3 characters long."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if clean_role not in ROLES:
        return False, f"Invalid role. Must be one of: {', '.join(ROLES)}."

    pwd_hash, salt = hash_password(password)
    now = datetime.now().isoformat()

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, salt, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (clean_user, pwd_hash, salt, clean_role, now)
        )
        conn.commit()
        return True, f"User '{clean_user}' created successfully with role {clean_role}."
    except sqlite3.IntegrityError:
        return False, f"Username '{clean_user}' already exists."
    finally:
        conn.close()


def get_all_users() -> list[dict]:
    """
    Retrieve all registered users without credentials.
    """
    init_auth_table()

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, role, created_at, last_login
            FROM users
            ORDER BY id ASC
            """
        )
        rows = cursor.fetchall()
        return [
            {
                "id": r[0],
                "username": r[1],
                "role": r[2],
                "created_at": r[3],
                "last_login": r[4]
            }
            for r in rows
        ]
    finally:
        conn.close()
