# app/security/test_device_trust.py

from datetime import datetime
import uuid
import pytest
pytestmark = pytest.mark.track_a
from app.security.bootstrap import build_pipeline 
from app.security.context import SecurityContext
from app.security.errors import SecurityPipelineError
from app.security.test_helpers.device_builder import build_device
from app.security.test_helpers.device_snapshot_builder import snapshot_from_device

# -------------------------------------------------
# Test setup
# -------------------------------------------------

pipeline = build_pipeline()

PRINCIPAL_ID = "user-123"
DEVICE_ID = "device-abc"
INTENT = "user.login"



def build_context(device_ctx):
    snapshot = snapshot_from_device(device_ctx)

    return SecurityContext(
        request_id=str(uuid.uuid4()),
        principal_id="user-123",
        intent="user.login",
        authenticated=True,
        device_id=snapshot.device_id,
        device=snapshot,      # ✅ snapshot only
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )

def run_test(name, fn):
    print(f"\n▶ {name}")
    try:
        fn()
        print("✅ PASS")
    except SecurityPipelineError as exc:
        print(f"❌ DENY → {exc}")
    except Exception as exc:
        print(f"🔥 ERROR → {exc}")


# -------------------------------------------------
# Test 1: Unregistered device → DENY
# -------------------------------------------------

def test_unregistered_device():
    device_ctx = build_device(
        device_id=DEVICE_ID,
        registered=False,
        state="active",
    )
    ctx = build_context(device_ctx)

    with pytest.raises(SecurityPipelineError, match="Device not registered"):
        pipeline.evaluate(ctx)


# -------------------------------------------------
# Test 2: Registered device + bad posture → DENY
# -------------------------------------------------

def test_registered_bad_posture():
    device_ctx = build_device(
        device_id=DEVICE_ID,
        registered=True,
        state="active",
        compromised=True,
    )
    ctx = build_context(device_ctx)

    with pytest.raises(SecurityPipelineError, match="Device integrity compromised"):
        pipeline.evaluate(ctx)

# -------------------------------------------------
# Test 3: Registered device + good posture → ALLOW
# -------------------------------------------------

def test_registered_good_posture():
    device_ctx = build_device(
        device_id=DEVICE_ID,
        registered=True,
        state="active",
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        clone_confirmed=False,
        replay_detected=False,
        secure_boot=True,
        compromised=False,
    )
    ctx = build_context(device_ctx)
    decision = pipeline.evaluate(ctx)

    assert decision.outcome.value == "allow"


# -------------------------------------------------
# Test 4: Device revoked → DENY
# -------------------------------------------------

def test_device_revoked():
    device_ctx = build_device(
        device_id=DEVICE_ID,
        registered=True,
        state="revoked",
    )
    ctx = build_context(device_ctx)

    with pytest.raises(SecurityPipelineError, match="Device revoked or lost"):
        pipeline.evaluate(ctx)

# -------------------------------------------------
# Test 5:hardware_backed = false
# -------------------------------------------------

def test_non_hardware_backed_key():
    device_ctx = build_device(
        device_id=DEVICE_ID,
        registered=True,
        state="active",
        hardware_backed=False,          # ❌ critical
        attestation_verified=True,
        binding_valid=True,
        clone_confirmed=False,
        replay_detected=False,
        secure_boot=True,
        compromised=False,
    )

    ctx = build_context(device_ctx)
    try:
        pipeline.evaluate(ctx)
        assert False, "Expected denial for non-hardware-backed key"
    except SecurityPipelineError as exc:
        assert "hardware-backed" in str(exc)

# -------------------------------------------------
# Test 6: attestation_verified = false
# -------------------------------------------------
def test_unverified_hardware_attestation():
    device_ctx = build_device(
        device_id=DEVICE_ID,
        registered=True,
        state="active",
        hardware_backed=True,
        attestation_verified=False,      # ❌ critical
        binding_valid=True,
        clone_confirmed=False,
        replay_detected=False,
        secure_boot=True,
        compromised=False,
    )

    ctx = build_context(device_ctx)
    try:
        pipeline.evaluate(ctx)
        assert False, "Expected denial for unverified attestation"
    except SecurityPipelineError as exc:
        assert "attestation" in str(exc)

# -------------------------------------------------
# Test 3: binding_valid = false
# -------------------------------------------------
def test_device_identity_binding_invalid():
    device_ctx = build_device(
        device_id=DEVICE_ID,
        registered=True,
        state="active",
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=False,             # ❌ critical
        clone_confirmed=False,
        replay_detected=False,
        secure_boot=True,
        compromised=False,
    )

    ctx = build_context(device_ctx)
    try:
        pipeline.evaluate(ctx)
        assert False, "Expected denial for invalid device binding"
    except SecurityPipelineError as exc:
        assert "binding" in str(exc)


# -------------------------------------------------
# Execute tests
# -------------------------------------------------

if __name__ == "__main__":
    run_test("Unregistered device", test_unregistered_device)
    run_test("Registered device + bad posture", test_registered_bad_posture)
    run_test("Registered device + good posture", test_registered_good_posture)
    run_test("Device revoked", test_device_revoked)


    # 🔒 New high-value security tests
    run_test("Non hardware-backed key", test_non_hardware_backed_key)
    run_test("Unverified hardware attestation", test_unverified_hardware_attestation)
    run_test("Invalid device identity binding", test_device_identity_binding_invalid)
