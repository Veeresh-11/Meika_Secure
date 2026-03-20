# app/security/persistence/evidence_repository.py

from typing import Optional
from app.security.evidence.models import EvidenceRecord
from app.security.persistence.db import get_connection


class PersistentEvidenceRepository:
    """
    Append-only evidence repository.
    """

    def append(self, record: EvidenceRecord) -> None:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO evidence_records (
                evidence_id,
                event_type,
                principal_id,
                intent,
                timestamp,
                details,
                previous_hash,
                hash
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            record.evidence_id,
            record.event_type,
            record.principal_id,
            record.intent,
            record.timestamp,
            record.details,
            record.previous_hash,
            record.hash,
        ))

        conn.commit()
        cur.close()
        conn.close()

    def last_hash(self) -> Optional[str]:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT hash FROM evidence_records
            ORDER BY timestamp DESC
            LIMIT 1
        """)

        row = cur.fetchone()
        cur.close()
        conn.close()

        return row["hash"] if row else None
