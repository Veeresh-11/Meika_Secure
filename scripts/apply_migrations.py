"""
Meika Secure ID
Migration Runner

Responsibilities:
- Create schema_migrations table
- Execute pending SQL migrations
- Record successful migrations
- Fail fast on errors
"""

from __future__ import annotations

import logging

from db_utils import (
    execute_sql_file,
    get_connection,
    ordered_migrations,
)

logger = logging.getLogger(__name__)

MIGRATION_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


def ensure_migration_table(cursor) -> None:
    """Create migration tracking table if it doesn't exist."""
    cursor.execute(MIGRATION_TABLE_SQL)


def applied_versions(cursor) -> set[str]:
    """Return already applied migration versions."""

    cursor.execute(
        """
        SELECT version
        FROM schema_migrations
        ORDER BY version
        """
    )

    return {row[0] for row in cursor.fetchall()}


def record_migration(cursor, version: str) -> None:
    """Record a successfully applied migration."""

    cursor.execute(
        """
        INSERT INTO schema_migrations(version)
        VALUES (%s)
        """,
        (version,),
    )


def apply() -> None:
    """
    Apply all pending migrations.
    """

    conn = get_connection()

    try:
        conn.autocommit = False

        with conn.cursor() as cur:

            ensure_migration_table(cur)

            completed = applied_versions(cur)

            for migration in ordered_migrations():

                if migration.name in completed:
                    logger.info(
                        "Skipping already applied migration %s",
                        migration.name,
                    )
                    continue

                logger.info(
                    "Applying %s",
                    migration.name,
                )

                execute_sql_file(cur, migration)

                record_migration(cur, migration.name)

                conn.commit()

                logger.info(
                    "Applied %s",
                    migration.name,
                )

    except Exception:

        conn.rollback()

        logger.exception(
            "Migration failed."
        )

        raise

    finally:

        conn.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )

    apply()