from pathlib import Path
import pytest
import database.database as db_mod
import services.containment as containment_mod


@pytest.fixture(autouse=True)
def isolate_test_database(tmp_path, monkeypatch):
    """
    Isolate test database to prevent pytest tests from mutating
    the production/demo sentinelx.db database.
    """
    test_db = str(tmp_path / "test_sentinelx.db")

    # Redirect module-level DATABASE_PATH in database and containment modules
    monkeypatch.setattr(db_mod, "DATABASE_PATH", test_db)
    monkeypatch.setattr(containment_mod, "DATABASE_PATH", Path(test_db))

    # Initialize clean schema for the test
    db_mod.initialize_database()
    containment_mod.initialize_containment_tables()

    yield test_db
