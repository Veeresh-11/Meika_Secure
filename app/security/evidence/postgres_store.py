import os
import time
from typing import List, Optional

from app.security.evidence.engine import GENESIS_HASH
from app.security.evidence.models import EvidenceRecord
from app.security.errors import SecurityInvariantViolation
from app.security.schema_guard import validate_schema


def _normalize_dsn(dsn: str) -> str:
    """
    Convert SQLAlchemy URLs into psycopg2 compatible URLs.
    """

    if dsn.startswith("postgresql+psycopg://"):
        return dsn.replace(
            "postgresql+psycopg://",
            "postgresql://",
            1,
        )

    return dsn


LOCK_ID = 987654321

MAX_RETRIES = 8

RETRY_DELAY = 0.025


class PostgresEvidenceStore:
    """
    Production append-only evidence ledger.

    Guarantees

    • SERIALIZABLE isolation
    • Advisory locking
    • Retry on serialization failure
    • Retry on deadlock
    • Fork detection
    • Sequence validation
    • Crash-safe commit
    """

    def __init__(self, dsn: str):

        self._dsn = dsn

        try:
            import psycopg2
            import psycopg2.extras

        except ImportError as exc:
            raise RuntimeError(
                "psycopg2 is required for PostgresEvidenceStore"
            ) from exc

        self._psycopg2 = psycopg2

        self._conn = psycopg2.connect(
            _normalize_dsn(dsn)
        )

        self._conn.autocommit = False

        self._conn.set_session(
            isolation_level="SERIALIZABLE"
        )

        schema_path = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "persistence",
                "evidence_schema.sql",
            )
        )

        validate_schema(
            self._dsn,
            schema_path,
        )

    # ---------------------------------------------------------
    # append
    # ---------------------------------------------------------

    def append(
        self,
        record: EvidenceRecord,
    ) -> str:

        for attempt in range(MAX_RETRIES):

            try:

                with self._conn.cursor() as cur:

                    #
                    # Cluster-wide lock
                    #

                    cur.execute(
                        "SELECT pg_advisory_lock(%s)",
                        (LOCK_ID,),
                    )

                    #
                    # Determine current chain head
                    #

                    cur.execute(
                        """
                        SELECT
                            sequence_number,
                            record_hash
                        FROM identity.evidence_ledger
                        ORDER BY sequence_number DESC
                        LIMIT 1
                        """
                    )

                    row = cur.fetchone()

                    if row is None:

                        current_sequence = -1
                        current_hash = None

                    else:

                        current_sequence = row[0]
                        current_hash = row[1]

                    #
                    # Genesis compatibility
                    #

                    expected_previous = record.previous_hash

                    if expected_previous == GENESIS_HASH:
                        expected_previous = None

                    #
                    # Fork detection
                    #

                    if current_hash != expected_previous:

                        raise SecurityInvariantViolation(
                            "FORK_DETECTED"
                        )

                    #
                    # Sequence validation
                    #

                    expected_sequence = current_sequence + 1

                    if record.sequence_number != expected_sequence:

                        raise SecurityInvariantViolation(
                            "SEQUENCE_COLLISION"
                        )

                    #
                    # Insert record
                    #

                    cur.execute(
                        """
                        INSERT INTO identity.evidence_ledger
                        (
                            sequence_number,
                            previous_hash,
                            payload_hash,
                            record_hash
                        )
                        VALUES
                        (
                            %s,
                            %s,
                            %s,
                            %s
                        )
                        """,
                        (
                            record.sequence_number,
                            None
                            if record.previous_hash == GENESIS_HASH
                            else record.previous_hash,
                            record.payload_hash,
                            record.record_hash,
                        ),
                    )

                self._conn.commit()

                return record.record_hash
            
            except (
                self._psycopg2.errors.SerializationFailure,
                self._psycopg2.errors.DeadlockDetected,
            ):

                self._conn.rollback()

                #
                # Exponential backoff
                #

                time.sleep(
                    RETRY_DELAY * (attempt + 1)
                )

                continue

            except Exception as exc:

                self._conn.rollback()

                raise SecurityInvariantViolation(
                    str(exc)
                ) from exc

            finally:

                try:

                    with self._conn.cursor() as cur:

                        cur.execute(
                            "SELECT pg_advisory_unlock(%s)",
                            (LOCK_ID,),
                        )

                    self._conn.commit()

                except Exception:

                    self._conn.rollback()

        raise SecurityInvariantViolation(
            "SERIALIZATION_RETRY_EXHAUSTED"
        )

    # ---------------------------------------------------------
    # last hash
    # ---------------------------------------------------------

    def last_hash(
        self,
    ) -> Optional[str]:

        with self._conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    record_hash
                FROM identity.evidence_ledger
                ORDER BY sequence_number DESC
                LIMIT 1
                """
            )

            row = cur.fetchone()

            if row is None:
                return None

            return row[0]

    # ---------------------------------------------------------
    # next sequence
    # ---------------------------------------------------------

    def next_sequence(
        self,
    ) -> int:

        with self._conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    COALESCE(MAX(sequence_number), -1) + 1
                FROM identity.evidence_ledger
                """
            )

            return cur.fetchone()[0]

    # ---------------------------------------------------------
    # read all
    # ---------------------------------------------------------

    def get_all(
        self,
    ) -> List[EvidenceRecord]:

        with self._conn.cursor(
            cursor_factory=self._psycopg2.extras.DictCursor,
        ) as cur:

            cur.execute(
                """
                SELECT
                    sequence_number,
                    previous_hash,
                    payload_hash,
                    record_hash
                FROM identity.evidence_ledger
                ORDER BY sequence_number ASC
                """
            )

            rows = cur.fetchall()

            return [
                EvidenceRecord(
                    sequence_number=row["sequence_number"],
                    previous_hash=(
                        row["previous_hash"]
                        if row["previous_hash"] is not None
                        else GENESIS_HASH
                    ),
                    payload_hash=row["payload_hash"],
                    record_hash=row["record_hash"],
                )
                for row in rows
            ]

    # ---------------------------------------------------------
    # close
    # ---------------------------------------------------------

    def close(self) -> None:

        try:

            self._conn.close()

        except Exception:

            pass