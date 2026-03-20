from datetime import datetime
from unittest.mock import Mock

from app.security.evidence.store import InMemoryEvidenceStore
from app.security.evidence.engine import build_evidence_record
from app.security.evidence.anchor_bridge import EvidenceAnchorBridge
from app.security.context import SecurityContext
from app.security.decision import SecurityDecision, DecisionOutcome
from app.security.track_d.export_soc2 import generate_soc2_export


def test_soc2_export_contains_anchor_receipts():
    store = InMemoryEvidenceStore()

    ctx = SecurityContext(
        request_id="1",
        principal_id="user",
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
    # 1️⃣ Add normal evidence record
    # -------------------------------------------------

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
    # 2️⃣ Anchor and record receipt into ledger
    # -------------------------------------------------

    mock_anchor = Mock()
    mock_anchor.anchor.return_value = {"provider": "mock", "status": "ok"}

    bridge = EvidenceAnchorBridge(mock_anchor)

    records = [store.get(h) for h in store.hashes()]
    bridge.seal_anchor_and_record(records, store, ctx)

    # -------------------------------------------------
    # 3️⃣ Convert ledger records to dict for export
    # -------------------------------------------------

    ledger_records = []

    for r in [store.get(h) for h in store.hashes()]:
        ledger_records.append(
            {
                "sequence_number": r.sequence_number,
                "previous_hash": r.previous_hash,
                "payload_hash": r.payload_hash,
                "record_hash": r.record_hash,
            }
        )

    # -------------------------------------------------
    # 4️⃣ Generate SOC2 export
    # -------------------------------------------------

    export = generate_soc2_export(
        evidence_records=ledger_records,
        kernel_version="1.0.0",
        export_period={
            "start": "2025-01-01T00:00:00Z",
            "end": "2025-01-31T23:59:59Z",
        },
        control_mapping={"CC7.2": "Evidence integrity enforced"},
    )

    # -------------------------------------------------
    # 5️⃣ Assertions
    # -------------------------------------------------

    assert "bundle_hash" in export
    assert "signature" in export
    assert "key_id" in export
    assert export["records"]  # not empty

    # Ensure at least one anchor receipt exists in ledger history
    # (second record created by bridge)
    assert len(export["records"]) >= 2
