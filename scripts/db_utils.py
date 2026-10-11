"""
Meika Secure ID
Database Utility Module

Provides:
- PostgreSQL connection helper
- Migration discovery
- Ordered migration loading
- SQL file execution helper
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import psycopg2
from psycopg2.extensions import connection

PROJECT_ROOT = str(Path(__file__).resolve().parents[1])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.config.settings import settings

logger = logging.getLogger(__name__)


def get_connection() -> connection:
    """
    Return a PostgreSQL connection using the application's
    authoritative database configuration.
    """

    return psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
    )


def migration_directory() -> Path:
    """
    Return the project's migration directory.
    """
    return Path(__file__).resolve().parent.parent / "migrations"


def ordered_migrations() -> list[Path]:
    """
    Return SQL migrations sorted in execution order.
    """

    migrations = sorted(migration_directory().glob("*.sql"))

    if not migrations:
        raise RuntimeError("No SQL migrations found.")

    return migrations


def execute_sql_file(cursor, migration: Path) -> None:
    """
    Execute a SQL migration file.
    """

    logger.info("Applying migration %s", migration.name)

    sql = migration.read_text(encoding="utf-8")

    cursor.execute(sql)
