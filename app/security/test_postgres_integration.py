import os
import pytest
from datetime import datetime
import psycopg2

from app.security.evidence.postgres_store import PostgresEvidenceStore
from app.security.evidence.engine import build_evidence_record
from app.security.evidence.verify import verify_chain
from app.security.context import SecurityContext
from app.security.decision import SecurityDecision, DecisionOutcome


POSTGRES_DSN = os.getenv("EVIDENCE_DSN")


@pytest.mark.postgres
@pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="Postgres DSN not configured",
)
def test_postgres_append_only_integrity():
    """
    Full production integration test:

    ✔ Append records
    ✔ Crash recovery
    ✔ Chain replay verification
    ✔ UPDATE blocked at DB level
    ✔ DELETE blocked at DB level
    ✔ Duplicate hash rejected
    """

    store = PostgresEvidenceStore(POSTGRES_DSN)

    ctx = SecurityContext(
        request_id="1",
        principal_id="u",
        intent="login",
        authenticated=True,
        device_id=None,
        device=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
        grant=None,
    )

    # -------------------------------------------------
    # Append records
    # -------------------------------------------------
    for _ in range(3):
        decision = SecurityDecision(
            outcome=DecisionOutcome.ALLOW,
            reason="ok",
            policy_version="test",
            evaluated_at=datetime.utcnow(),
        )

        record = build_evidence_record(
            context=ctx,
            policy=None,
            risk=None,
            authority=[],
            decision=decision,
            extra_metadata={},
            store=store,
        )

        store.append(record)

    # -------------------------------------------------
    # Crash simulation
    # -------------------------------------------------
    new_store = PostgresEvidenceStore(POSTGRES_DSN)
    records = new_store.get_all()

    assert verify_chain(records) is True

    # -------------------------------------------------
    # UPDATE should fail
    # -------------------------------------------------
    conn = psycopg2.connect(POSTGRES_DSN)
    cur = conn.cursor()

    with pytest.raises(Exception):
        cur.execute(
            "UPDATE evidence_ledger SET payload_hash='x' WHERE sequence_number=0"
        )
        conn.commit()

    conn.rollback()

    # -------------------------------------------------
    # DELETE should fail
    # -------------------------------------------------
    with pytest.raises(Exception):
        cur.execute("DELETE FROM evidence_ledger WHERE sequence_number=0")
        conn.commit()

    conn.rollback()

    # -------------------------------------------------
    # Duplicate insert must fail
    # -------------------------------------------------
    first_record = records[0]

    with pytest.raises(Exception):
        cur.execute(
            """
            INSERT INTO evidence_ledger
            (sequence_number, previous_hash, payload_hash, record_hash)
            VALUES (%s, %s, %s, %s)
            """,
            (
                first_record.sequence_number,
                first_record.previous_hash,
                first_record.payload_hash,
                first_record.record_hash,
            ),
        )
        conn.commit()

    conn.close()
