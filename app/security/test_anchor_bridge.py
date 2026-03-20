from datetime import datetime
from unittest.mock import Mock

from app.security.evidence.store import InMemoryEvidenceStore
from app.security.evidence.engine import build_evidence_record
from app.security.evidence.anchor_bridge import EvidenceAnchorBridge
from app.security.context import SecurityContext
from app.security.decision import SecurityDecision, DecisionOutcome


def test_seal_and_anchor_bridge():
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

    records = [store.get(h) for h in store.hashes()]

    mock_anchor = Mock()
    mock_anchor.anchor.return_value = {"status": "anchored"}

    bridge = EvidenceAnchorBridge(mock_anchor)

    result = bridge.seal_and_anchor(records)

    assert result["anchor_receipt"]["status"] == "anchored"
    mock_anchor.anchor.assert_called_once()
