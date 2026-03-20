# app/security/test_security_invariants.py

import pytest
pytestmark = pytest.mark.track_a
from datetime import datetime

from app.security.context import SecurityContext
from app.security.device_snapshot import DeviceSnapshot
from app.security.device.context import (
    DeviceContext,
    DeviceIdentityContext,
    DevicePostureContext,
)


def test_security_context_is_immutable():
    """
    Sprint A1 + A2 invariant:

    - SecurityContext is immutable after construction
    - Only DeviceSnapshot may cross the security boundary
    """

    # --- Domain device (never passed directly) ---
    identity = DeviceIdentityContext(
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        clone_confirmed=False,
        replay_detected=False,
        last_attested_at=datetime.utcnow(),
    )

    posture = DevicePostureContext(
        secure_boot=True,
        compromised=False,
    )

    device = DeviceContext(
        device_id="device-1",
        registered=True,
        state="active",
        identity=identity,
        posture=posture,
    )

    # --- Snapshot (boundary object) ---
    snapshot = DeviceSnapshot(
        device_id=device.device_id,
        registered=device.registered,
        compromised=device.posture.compromised,
        clone_confirmed=device.identity.clone_confirmed,
    )

    ctx = SecurityContext(
        request_id="req-1",
        principal_id="user-1",
        intent="GET /protected",
        authenticated=True,
        device_id=snapshot.device_id,
        device=snapshot,          # ✅ snapshot only
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )

    # --- Immutability enforcement ---
    with pytest.raises(Exception):
        ctx.device = None
