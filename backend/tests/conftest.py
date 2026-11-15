import os
import pytest

# Enforce isolated test database for all automated testing
os.environ["DATABASE_URL"] = "sqlite:///./data/test_forensix.db"

from backend.app.core.database import Base, engine, init_db


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    init_db()
    yield

