import os
from pathlib import Path


TEST_DB_PATH = Path(__file__).resolve().parents[1] / ".pytest-sentinelforge.db"

# Point imports at an isolated SQLite file before any application modules load.
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH.as_posix()}"

if TEST_DB_PATH.exists():
    TEST_DB_PATH.unlink()


def pytest_sessionfinish(session, exitstatus):
    try:
        from sqlalchemy.orm import close_all_sessions
        from src.memory import database

        close_all_sessions()
        database.engine.dispose()
    except Exception:
        pass

    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
