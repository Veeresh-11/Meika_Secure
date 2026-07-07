import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config.settings import settings
import app.db
from app.db import Base


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

    Base.metadata.create_all(bind=engine)

    yield

    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session():

    connection = engine.connect()

    transaction = connection.begin()

    session = SessionLocal(bind=connection)

    try:
        yield session

    finally:
        session.close()
        transaction.rollback()
        connection.close()