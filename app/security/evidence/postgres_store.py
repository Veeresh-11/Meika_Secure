import os
from typing import Optional, List

from app.security.evidence.models import EvidenceRecord
from app.security.errors import SecurityInvariantViolation
from app.security.schema_guard import validate_schema


# Global advisory lock ID (constant across cluster)
LOCK_ID = 987654321


class PostgresEvidenceStore:
    """
    Production-grade append-only evidence store (Postgres).

    Hardened Guarantees:
    - SERIALIZABLE isolation
    - Advisory locking (cross-process safe)
    - Fork detection
    - Sequence collision protection
    - Strict hash chaining
    - Crash-safe commits
    - Schema checksum verified at startup
    """

    def __init__(self, dsn: str):
        self._dsn = dsn

        # ✅ Lazy import (CI-safe)
        try:
            import psycopg2
        except ImportError:
            raise RuntimeError("psycopg2 is required for PostgresEvidenceStore")

        self._psycopg2 = psycopg2

        # ✅ Single connection
        self._conn = psycopg2.connect(dsn)
        self._conn.autocommit = False

        # Enforce strongest isolation level
        self._conn.set_session(isolation_level="SERIALIZABLE")

        schema_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "persistence",
            "evidence_schema.sql",
        )

        schema_path = os.path.abspath(schema_path)
        validate_schema(self._dsn, schema_path)

    # ---------------------------------------------------------
    # Core Operations
    # ---------------------------------------------------------

    def append(self, record: EvidenceRecord) -> str:
        try:
            with self._conn.cursor() as cur:

                # 🔒 Acquire advisory lock
                cur.execute("SELECT pg_advisory_lock(%s);", (LOCK_ID,))

                # 🔍 Verify chain head
                cur.execute(
                    """
                    SELECT record_hash
                    FROM evidence_ledger
                    ORDER BY sequence_number DESC
                    LIMIT 1
                    """
                )
                row = cur.fetchone()
                current_head = row[0] if row else None

                expected_previous = record.previous_hash or None

                if current_head != expected_previous:
                    raise SecurityInvariantViolation("FORK_DETECTED")

                # 🔢 Verify sequence
                cur.execute(
                    """
                    SELECT COALESCE(MAX(sequence_number), -1) + 1
                    FROM evidence_ledger
                    """
                )
                next_seq = cur.fetchone()[0]

                if next_seq != record.sequence_number:
                    raise SecurityInvariantViolation("SEQUENCE_COLLISION")

                # 🧱 Insert record
                cur.execute(
                    """
                    INSERT INTO evidence_ledger
                    (sequence_number, previous_hash, payload_hash, record_hash)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        record.sequence_number,
                        record.previous_hash,
                        record.payload_hash,
                        record.record_hash,
                    ),
                )

            self._conn.commit()
            return record.record_hash

        except Exception as e:
            self._conn.rollback()
            raise SecurityInvariantViolation(str(e))

        finally:
            # 🔓 Always release lock
            try:
                with self._conn.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s);", (LOCK_ID,))
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    # ---------------------------------------------------------

    def last_hash(self) -> Optional[str]:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                SELECT record_hash
                FROM evidence_ledger
                ORDER BY sequence_number DESC
                LIMIT 1
                """
            )
            row = cur.fetchone()
            return row[0] if row else None

    # ---------------------------------------------------------

    def next_sequence(self) -> int:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                SELECT COALESCE(MAX(sequence_number), -1) + 1
                FROM evidence_ledger
                """
            )
            return cur.fetchone()[0]

    # ---------------------------------------------------------

    def get_all(self) -> List[EvidenceRecord]:
        with self._conn.cursor(
            cursor_factory=self._psycopg2.extras.DictCursor  # ✅ FIXED
        ) as cur:
            cur.execute(
                """
                SELECT sequence_number,
                       previous_hash,
                       payload_hash,
                       record_hash
                FROM evidence_ledger
                ORDER BY sequence_number ASC
                """
            )

            rows = cur.fetchall()

            return [
                EvidenceRecord(
                    sequence_number=row["sequence_number"],
                    previous_hash=row["previous_hash"],
                    payload_hash=row["payload_hash"],
                    record_hash=row["record_hash"],
                )
                for row in rows
            ]