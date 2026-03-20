import pytest

pytestmark = [
    pytest.mark.track_b,
    pytest.mark.evidence,
]

from datetime import datetime

from app.security.device_snapshot import DeviceSnapshot
from app.security.context import SecurityContext
from app.security.decision import SecurityDecision, DecisionOutcome
from app.security.evidence.writer import EvidenceWriter
from app.security.test_helpers.device_builder import build_device


# Evidence store + writer
from app.security.evidence.store import InMemoryEvidenceStore

store = InMemoryEvidenceStore()

writer = EvidenceWriter(store)

# Build device
device = build_device(
    device_id="device-1",
    registered=True,
    state="active",
    secure_boot=True,
    compromised=False,
    clone_confirmed=False,
)

# Snapshot
snapshot = DeviceSnapshot(
    device_id=device.device_id,
    registered=device.registered,
    compromised=device.compromised,
    clone_confirmed=device.clone_confirmed,
)

# Security context
ctx = SecurityContext(
    request_id="req-1",
    principal_id="user-1",
    intent="authentication.attempt",
    authenticated=True,
    device_id=device.device_id,
    device=snapshot,
    risk_signals={},
    request_time=datetime.utcnow(),
    metadata={},
)

# Write evidence
for i in range(3):
    decision = SecurityDecision(
        outcome=DecisionOutcome.ALLOW,
        reason=f"test-{i}",
        policy_version="v1",
        evaluated_at=datetime.utcnow(),
    )
    writer.write_decision(ctx, decision)

hashes = store.hashes()

# Validate chaining
for i in range(1, len(hashes)):
    prev = store.get(hashes[i - 1])
    curr = store.get(hashes[i])
    assert curr.previous_hash == prev.record_hash

