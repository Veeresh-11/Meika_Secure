import uuid

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config.settings import settings
import app.db


TEST_TENANT_ID = uuid.UUID(
    "00000000-0000-4000-8000-000000000001"
)

TEST_TENANT_NAME = "Meika Legacy"


TEST_DATABASE_URL = (
    f"postgresql+psycopg://"
    f"{settings.db_user}:"
    f"{settings.db_password}@"
    f"{settings.db_host}:"
    f"{settings.db_port}/"
    f"meika_secure_id_test"
)


engine = create_engine(
    TEST_DATABASE_URL,
    pool_pre_ping=True,
)


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


@pytest.fixture(scope="session", autouse=True)
def create_database():
    """
    The test database is provisioned by the authoritative SQL
    migration chain.

    Pytest must not create or drop the database schema through
    SQLAlchemy metadata because doing so bypasses the migration
    chain being tested.
    """
    yield


@pytest.fixture
def db_session():
    """
    Provide a database session for each test.

    The connection-level transaction is rolled back after the test
    when it remains active, preventing test data from leaking into
    subsequent tests.
    """
    connection = engine.connect()
    transaction = connection.begin()
    session = SessionLocal(bind=connection)

    try:
        yield session

    finally:
        session.close()

        if transaction.is_active:
            transaction.rollback()

        connection.close()