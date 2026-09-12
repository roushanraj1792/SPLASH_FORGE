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


def test_demo_users_seed_and_auth():
    init_auth_table()

    # Authenticate seeded admin
    admin_user = authenticate_user("admin", "SentinelX@Admin2026")
    assert admin_user is not None
    assert admin_user["username"] == "admin"
    assert admin_user["role"] == "ADMIN"
    assert admin_user["last_login"] is not None

    # Authenticate seeded analyst
    analyst_user = authenticate_user("analyst", "SentinelX@Analyst2026")
    assert analyst_user is not None
    assert analyst_user["username"] == "analyst"
    assert analyst_user["role"] == "ANALYST"

    # Bad password
    bad_auth = authenticate_user("admin", "WrongPassword")
    assert bad_auth is None

    # Nonexistent user
    unknown_auth = authenticate_user("ghost_user", "AnyPassword")
    assert unknown_auth is None


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
