from app.security.evidence.store import InMemoryEvidenceStore
from app.security.evidence.engine import build_evidence_record
from app.security.evidence.verify import verify_chain
from app.security.context import SecurityContext
from app.security.decision import SecurityDecision, DecisionOutcome
from datetime import datetime


def test_chain_integrity_verification():
    store = InMemoryEvidenceStore()

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

    # Append 3 records
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

    records = [store.get(h) for h in store.hashes()]

    assert verify_chain(records) is True
