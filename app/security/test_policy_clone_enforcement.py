import pytest

pytestmark = pytest.mark.track_a

import uuid
from datetime import datetime

import pytest

from app.security.bootstrap import build_pipeline
from app.security.context import SecurityContext
from app.security.device_snapshot import DeviceSnapshot
from app.security.errors import SecurityPipelineError
from app.security.results import DenyReason
from app.security.test_helpers.device_builder import build_device


def test_cloned_device_token_denied():
    """
    Sprint A2 invariant:
    - Clone detection is structurally dominant
    - Policy must NEVER run
    - Deny reason must be canonical (no magic strings)
    """

    pipeline = build_pipeline()

    # Domain device (used ONLY to create snapshot)
    device = build_device(
        device_id="device-clone",
        registered=True,
        state="active",
        clone_confirmed=True,   # 🔥 cloned device
        secure_boot=True,
        compromised=False,
    )

    # 🔒 Snapshot is the ONLY object crossing boundary
    snapshot = DeviceSnapshot(
        device_id=device.device_id,
        registered=device.registered,
        compromised=device.compromised,
        clone_confirmed=device.clone_confirmed,
    )

    ctx = SecurityContext(
        request_id=str(uuid.uuid4()),
        principal_id="user-1",
        intent="authentication.attempt",
        authenticated=True,
        device_id=snapshot.device_id,
        device=snapshot,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )

    # ✅ Correct assertion (no regex, no strings)
    with pytest.raises(SecurityPipelineError) as exc:
        pipeline.evaluate(ctx)

    assert exc.value.reason == DenyReason.DEVICE_CLONED
