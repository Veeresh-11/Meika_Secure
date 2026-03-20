from datetime import datetime
from unittest.mock import Mock

from app.security.evidence.store import InMemoryEvidenceStore
from app.security.evidence.engine import build_evidence_record
from app.security.evidence.anchor_bridge import EvidenceAnchorBridge
from app.security.context import SecurityContext
from app.security.decision import SecurityDecision, DecisionOutcome


def test_anchor_receipt_recorded_in_ledger():
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

    mock_anchor = Mock()
    mock_anchor.anchor.return_value = {"provider": "mock", "status": "ok"}

    bridge = EvidenceAnchorBridge(mock_anchor)

    records = [store.get(h) for h in store.hashes()]
    bridge.seal_anchor_and_record(records, store, ctx)

    # Now ledger should contain 2 records
    assert len(store.hashes()) == 2
