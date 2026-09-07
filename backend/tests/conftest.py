"""Test fixtures and configurations for backend test suite."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentshield.api.app import create_app
from agentshield.core.config import Settings, reset_settings
from agentshield.persistence.db import reset_db, run_migrations


@pytest.fixture
def temp_data_dir() -> Generator[Path]:
    """Provide an isolated temporary directory for test storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_settings(temp_data_dir: Path) -> Generator[Settings]:
    """Provide isolated application settings pointing to temporary storage."""
    settings = Settings(
        host="127.0.0.1",
        port=8765,
        data_dir=temp_data_dir,
        profile="balanced",
        dev_mode=True,
        log_level="DEBUG",
        cors_allowed_origins=[
            "http://127.0.0.1:8765",
            "http://localhost:8765",
            "http://127.0.0.1:5173",
        ],
    )
    reset_settings(settings)
    reset_db()
    run_migrations(settings.effective_database_url)
    yield settings
    reset_db()
    reset_settings(None)


@pytest.fixture
def client(test_settings: Settings) -> Generator[TestClient]:
    """Provide a FastAPI TestClient configured with test settings."""
    app = create_app(test_settings)
    with TestClient(app, base_url="http://127.0.0.1:8765") as c:
        yield c
