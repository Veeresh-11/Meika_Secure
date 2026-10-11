"""
Meika Secure ID
Database Bootstrap

Single entry point for all database initialization.

Responsibilities:
- Verify PostgreSQL connectivity
- Apply pending migrations
- Validate final schema
"""

from __future__ import annotations

import logging
import sys
import time

from apply_migrations import apply
from db_utils import get_connection
from validate_schema import validate

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger(__name__)


def wait_for_database(max_attempts: int = 30, delay: int = 2) -> None:
    """
    Wait until PostgreSQL is accepting connections.
    """

    for attempt in range(1, max_attempts + 1):
        try:
            conn = get_connection()
            conn.close()

            logger.info("PostgreSQL is ready.")
            return

        except Exception:
            logger.info(
                "Waiting for PostgreSQL (%d/%d)...",
                attempt,
                max_attempts,
            )
            time.sleep(delay)

    raise RuntimeError("Unable to connect to PostgreSQL.")


def bootstrap() -> None:
    """
    Complete database bootstrap.
    """

    logger.info("=" * 60)
    logger.info("Bootstrapping Meika Secure ID Database")
    logger.info("=" * 60)

    wait_for_database()

    logger.info("Running database migrations...")
    apply()

    logger.info("Validating database schema...")
    validate()

    logger.info("Database bootstrap completed successfully.")


if __name__ == "__main__":
    try:
        bootstrap()

    except Exception:
        logger.exception("Bootstrap failed.")
        sys.exit(1)