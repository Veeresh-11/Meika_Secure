import pytest

pytestmark = pytest.mark.track_a

from datetime import datetime

from app.security.bootstrap import build_pipeline
from app.security.context import SecurityContext
from app.security.device_snapshot import DeviceSnapshot
from app.security.test_helpers.device_builder import build_device

pipeline = build_pipeline()

device = build_device(
    device_id= None,
    registered=True,
    state="active",
    secure_boot=True,
    compromised=False,
    clone_confirmed=False,
)

snapshot = DeviceSnapshot(
    device_id=device.device_id,
    registered=device.registered,
    compromised=device.compromised,
    clone_confirmed=device.clone_confirmed,
)

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

decision = pipeline.evaluate(ctx)
assert decision is not None
