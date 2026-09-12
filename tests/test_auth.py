import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.auth import (
    hash_password,
    verify_password,
    init_auth_table,
    authenticate_user,
    create_user,
    get_all_users,
)


def test_password_hashing():
    pwd = "SecretPassword123!"
    h, s = hash_password(pwd)
    assert len(h) == 64  # SHA256 hex
    assert len(s) == 32  # 16 bytes hex

    assert verify_password(pwd, s, h) is True
    assert verify_password("WrongPassword", s, h) is False
    assert verify_password("", s, h) is False


def test_analyst_demo_auth_accepted():
    init_auth_table()
    analyst_user = authenticate_user("analyst", "SentinelX@Analyst2026")
    assert analyst_user is not None
    assert analyst_user["username"] == "analyst"
    assert analyst_user["role"] == "ANALYST"
    assert analyst_user["last_login"] is not None


def test_old_admin_demo_password_rejected(monkeypatch):
    # Ensure legacy hardcoded demo password is never accepted
    monkeypatch.delenv("SENTINELX_ADMIN_PASSWORD", raising=False)
    init_auth_table()
    bad_admin = authenticate_user("admin", "SentinelX@Admin2026")
    assert bad_admin is None


def test_admin_requires_private_env_password(monkeypatch):
    # Case 1: When SENTINELX_ADMIN_PASSWORD is empty or unset, admin is disabled
    monkeypatch.delenv("SENTINELX_ADMIN_PASSWORD", raising=False)
    assert authenticate_user("admin", "AnyPassword") is None

    # Case 2: When SENTINELX_ADMIN_PASSWORD is set in environment
    test_secret = "PrivateHostSecret!2026#Secure"
    monkeypatch.setenv("SENTINELX_ADMIN_PASSWORD", test_secret)

    # Legacy demo password is still rejected
    assert authenticate_user("admin", "SentinelX@Admin2026") is None

    # Wrong secret is rejected
    assert authenticate_user("admin", "WrongHostSecret") is None

    # Valid private password is accepted
    admin_user = authenticate_user("admin", test_secret)
    assert admin_user is not None
    assert admin_user["username"] == "admin"
    assert admin_user["role"] == "ADMIN"
    assert admin_user["last_login"] is not None


def test_invalid_credentials_rejected():
    init_auth_table()
    # Bad analyst password
    assert authenticate_user("analyst", "WrongPassword123") is None
    # Empty credentials
    assert authenticate_user("", "") is None
    assert authenticate_user("analyst", "") is None
    assert authenticate_user("", "some_password") is None
    # Nonexistent user
    assert authenticate_user("ghost_user", "AnyPassword") is None


def test_admin_and_analyst_role_isolation(monkeypatch):
    test_secret = "PrivateHostSecret!2026#Secure"
    monkeypatch.setenv("SENTINELX_ADMIN_PASSWORD", test_secret)

    admin_user = authenticate_user("admin", test_secret)
    analyst_user = authenticate_user("analyst", "SentinelX@Analyst2026")

    assert admin_user is not None
    assert analyst_user is not None

    # Roles and privileges must remain strictly isolated
    assert admin_user["role"] == "ADMIN"
    assert analyst_user["role"] == "ANALYST"
    assert admin_user["id"] != analyst_user["id"]
    assert admin_user["username"] != analyst_user["username"]


def test_user_creation_and_roles():
    init_auth_table()

    # Success creation
    ok, msg = create_user("sec_auditor", "AuditorPass2026!", role="AUDITOR")
    assert ok is True

    # Authenticate newly created user
    auditor = authenticate_user("sec_auditor", "AuditorPass2026!")
    assert auditor is not None
    assert auditor["role"] == "AUDITOR"

    # Duplicate username should fail
    dup_ok, dup_msg = create_user("sec_auditor", "AnotherPassword!")
    assert dup_ok is False
    assert "already exists" in dup_msg

    # Too short username
    short_ok, _ = create_user("ab", "ValidPassword123")
    assert short_ok is False

    # Too short password
    short_pwd, _ = create_user("valid_user", "short")
    assert short_pwd is False

    # Invalid role
    bad_role, _ = create_user("role_test", "ValidPassword123", role="SUPERUSER")
    assert bad_role is False


def test_get_all_users():
    init_auth_table()
    users = get_all_users()
    assert len(users) >= 2
    usernames = [u["username"] for u in users]
    assert "admin" in usernames
    assert "analyst" in usernames


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))
