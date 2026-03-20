from datetime import datetime

from app.security.evidence.store import InMemoryEvidenceStore
from app.security.evidence.engine import build_evidence_record
from app.security.evidence.seal import create_seal_snapshot
from app.security.context import SecurityContext
from app.security.decision import SecurityDecision, DecisionOutcome


def test_root_seal_snapshot():
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
    seal = create_seal_snapshot(records)

    assert "root_hash" in seal["snapshot"]
    assert "snapshot_hash" in seal
