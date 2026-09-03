"""SQLite database engine, connection configuration, WAL mode, and session management."""

import contextlib
import sqlite3
import sys
from collections.abc import Generator
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from agentshield.core.config import ensure_secure_dir, get_settings
from agentshield.core.logging import get_logger

logger = get_logger("agentshield.persistence.db")


def configure_sqlite_pragmas(dbapi_connection: Any, connection_record: Any) -> None:
    """Set essential SQLite pragmas for performance, concurrency, and integrity."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


def ensure_db_file_permissions(database_url: str) -> None:
    """Ensure the SQLite database file and parent directory have restricted permissions."""
    if database_url.startswith("sqlite:///"):
        file_path_str = database_url.replace("sqlite:///", "")
        if file_path_str and file_path_str != ":memory:":
            db_path = Path(file_path_str).resolve()
            ensure_secure_dir(db_path.parent)
            if db_path.exists() and sys.platform != "win32":
                with contextlib.suppress(OSError):
                    db_path.chmod(0o600)


def create_db_engine(database_url: str | None = None) -> Engine:
    """Create SQLAlchemy engine configured for SQLite with WAL mode and pragmas."""
    settings = get_settings()
    url = database_url or settings.effective_database_url
    ensure_db_file_permissions(url)

    engine = create_engine(
        url,
        echo=False,
        connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
    )

    if url.startswith("sqlite"):
        event.listen(engine, "connect", configure_sqlite_pragmas)

    return engine


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Get or initialize singleton database engine."""
    global _engine, _session_factory
    if _engine is None:
        _engine = create_db_engine()
        _session_factory = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Get or initialize singleton session factory."""
    global _session_factory
    if _session_factory is None:
        get_engine()
    assert _session_factory is not None
    return _session_factory


@contextlib.contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Provide a transactional database session context."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for obtaining a database session."""
    with get_db_session() as session:
        yield session


def run_migrations(database_url: str | None = None) -> None:
    """Run Alembic database migrations up to head."""
    from alembic import command
    from alembic.config import Config

    settings = get_settings()
    url = database_url or settings.effective_database_url
    ensure_db_file_permissions(url)

    # Resolve alembic.ini location
    current_file = Path(__file__).resolve()
    # backend/src/agentshield/persistence/db.py -> backend/alembic.ini
    backend_dir = current_file.parent.parent.parent.parent
    alembic_ini_path = backend_dir / "alembic.ini"

    alembic_cfg = Config(str(alembic_ini_path))
    alembic_cfg.set_main_option("script_location", str(backend_dir / "migrations"))
    alembic_cfg.set_main_option("sqlalchemy.url", url)

    logger.info("Running database migrations on %s", url)
    command.upgrade(alembic_cfg, "head")
    ensure_db_file_permissions(url)
