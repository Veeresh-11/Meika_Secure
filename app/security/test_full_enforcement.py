# app/security/test_full_enforcement.py
#
# Full enforcement test (pipeline-level, no HTTP layer)
import pytest

pytestmark = [
    pytest.mark.track_b,
    pytest.mark.kernel,
]
from datetime import datetime
import uuid
from app.security.bootstrap import build_pipeline
from app.security.context import SecurityContext
from app.security.errors import SecurityPipelineError
from app.security.test_helpers.device_builder import build_device
from app.security.device_snapshot import DeviceSnapshot

def test_cloned_device_token_denied():
    pipeline = build_pipeline()

    device_ctx= build_device(
        device_id="device-clone",
        registered=True,
        state="active",
        clone_confirmed=True,   # 🔥 clone detected
        secure_boot=True,
        compromised=False,
    )
    device = DeviceSnapshot.from_context(device_ctx)

    ctx = SecurityContext(
        request_id=str(uuid.uuid4()),
        principal_id="user-1",
        intent="authentication.attempt",
        authenticated=True,
        device_id=device.device_id,
        device=device,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )

    # DENY is enforced via exception — this IS the assertion
    with pytest.raises(SecurityPipelineError, match="cloning"):
        pipeline.evaluate(ctx)

