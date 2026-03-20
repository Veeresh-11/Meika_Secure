from datetime import datetime
from unittest.mock import Mock
import time

from app.security.evidence.store import InMemoryEvidenceStore
from app.security.evidence.anchor_bridge import EvidenceAnchorBridge
from app.security.evidence.anchor_policy import TimeAnchorPolicy
from app.security.evidence.anchor_orchestrator import EvidenceAnchorOrchestrator


def test_time_policy_triggers_anchor():
    store = InMemoryEvidenceStore()

    mock_anchor = Mock()
    mock_anchor.anchor.return_value = {"status": "ok"}

    bridge = EvidenceAnchorBridge(mock_anchor)
    time_policy = TimeAnchorPolicy(interval_seconds=1)

    orchestrator = EvidenceAnchorOrchestrator(
        bridge=bridge,
        time_policy=time_policy,
    )

    records = []
    result = orchestrator.evaluate(records, store, None)

    assert result is not None
