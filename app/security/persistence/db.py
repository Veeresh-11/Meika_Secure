# app/security/persistence/db.py

from app.config.settings import settings


def get_connection():
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except ImportError:
        raise RuntimeError("psycopg2 is required for database connections")

    return psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        user=settings.db_user,
        password=settings.db_password,
        dbname=settings.db_name,
        cursor_factory=RealDictCursor,
    )