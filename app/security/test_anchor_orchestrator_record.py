from datetime import datetime
from unittest.mock import Mock

from app.security.evidence.store import InMemoryEvidenceStore
from app.security.evidence.engine import build_evidence_record
from app.security.evidence.anchor_bridge import EvidenceAnchorBridge
from app.security.evidence.anchor_policy import AnchorPolicy
from app.security.evidence.anchor_orchestrator import EvidenceAnchorOrchestrator
from app.security.context import SecurityContext
from app.security.decision import SecurityDecision, DecisionOutcome


def test_record_threshold_triggers_anchor():
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

    mock_anchor = Mock()
    mock_anchor.anchor.return_value = {"status": "ok"}

    bridge = EvidenceAnchorBridge(mock_anchor)
    policy = AnchorPolicy(threshold=3)

    orchestrator = EvidenceAnchorOrchestrator(
        bridge=bridge,
        record_policy=policy,
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
    result = orchestrator.evaluate(records, store, ctx)

    assert result is not None
    assert mock_anchor.anchor.called
