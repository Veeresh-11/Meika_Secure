import uuid
from datetime import datetime

from app.db.device_models import Device

from app.security.device.constants import (
    DEVICE_STATE_ACTIVE,
    DEVICE_STATE_REVOKED,
    DEVICE_STATE_SUSPENDED,
    TRUST_HIGH,
    TRUST_MEDIUM,
    TRUST_LOW,
    TRUST_CRITICAL,
)

from app.security.device.trust_context import DeviceTrustContext
from app.security.device.trust_evaluator import TrustEvaluator
from app.security.device.trust_score import (
    HARDWARE_BACKED_BONUS,
    ATTESTATION_VERIFIED_BONUS,
    KNOWN_DEVICE_BONUS,
    LOW_CREDENTIAL_COUNT_BONUS,)


def make_device(
    *,
    hardware_backed=True,
    attestation_verified=True,
    state=DEVICE_STATE_ACTIVE,
):
    return Device(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        device_identifier="device-001",
        device_name="Pixel 9",
        device_type="phone",
        hardware_backed=hardware_backed,
        attestation_verified=attestation_verified,
        trust_level="LOW",
        state=state,
        registered_at=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


def test_high_trust_device():

    context = DeviceTrustContext(
        device=make_device(),
        credential_count=1,
        session_count=1,
        failed_auth_count=0,
        recent_replay_detected=False,
        impossible_travel=False,
        behavior_anomaly=False,
    )

    result = TrustEvaluator.evaluate(context)

    assert result.trust_level == TRUST_HIGH
    assert result.risk_level == "LOW"
    assert result.score >= 80


def test_failed_authentication_penalty():

    context = DeviceTrustContext(
        device=make_device(),
        credential_count=1,
        session_count=1,
        failed_auth_count=3,
        recent_replay_detected=False,
        impossible_travel=False,
        behavior_anomaly=False,
    )

    result = TrustEvaluator.evaluate(context)

    assert result.score < 80


def test_replay_attack():

    context = DeviceTrustContext(
        device=make_device(),
        credential_count=1,
        session_count=1,
        failed_auth_count=0,
        recent_replay_detected=True,
        impossible_travel=False,
        behavior_anomaly=False,
    )

    result = TrustEvaluator.evaluate(context)

    assert result.risk_level in ("HIGH", "CRITICAL")


def test_impossible_travel():

    context = DeviceTrustContext(
        device=make_device(),
        credential_count=1,
        session_count=1,
        failed_auth_count=0,
        recent_replay_detected=False,
        impossible_travel=True,
        behavior_anomaly=False,
    )

    result = TrustEvaluator.evaluate(context)

    assert result.score < 80


def test_behavior_anomaly():

    context = DeviceTrustContext(
        device=make_device(),
        credential_count=1,
        session_count=1,
        failed_auth_count=0,
        recent_replay_detected=False,
        impossible_travel=False,
        behavior_anomaly=True,
    )

    result = TrustEvaluator.evaluate(context)

    assert result.score < 80


def test_suspended_device():

    context = DeviceTrustContext(
        device=make_device(
            state=DEVICE_STATE_SUSPENDED,
        ),
        credential_count=1,
        session_count=1,
        failed_auth_count=0,
        recent_replay_detected=False,
        impossible_travel=False,
        behavior_anomaly=False,
    )

    result = TrustEvaluator.evaluate(context)

    assert result.trust_level in (
        TRUST_MEDIUM,
        TRUST_LOW,
    )


def test_revoked_device():

    context = DeviceTrustContext(
        device=make_device(
            state=DEVICE_STATE_REVOKED,
        ),
        credential_count=1,
        session_count=1,
        failed_auth_count=0,
        recent_replay_detected=False,
        impossible_travel=False,
        behavior_anomaly=False,
    )

    result = TrustEvaluator.evaluate(context)

    assert result.trust_level == TRUST_CRITICAL
    assert result.risk_level == "CRITICAL"
    
def test_medium_trust_device():

    context = DeviceTrustContext(
        device=make_device(),
        credential_count=2,
        session_count=1,
        failed_auth_count=2,
        recent_replay_detected=False,
        impossible_travel=False,
        behavior_anomaly=False,
    )

    result = TrustEvaluator.evaluate(context)

    #
    # Score:
    # 30 + 30 + 20 = 80
    # credential_count != 1 => +0
    # failed_auth_count=2 => -20
    #
    # Final = 60
    #

    assert result.score == 60
    assert result.trust_level == TRUST_MEDIUM
    assert result.risk_level == "MEDIUM"
    
def test_attestation_without_hardware():

    context = DeviceTrustContext(
        device=make_device(
            hardware_backed=False,
            attestation_verified=True,
        ),
        credential_count=1,
        session_count=1,
        failed_auth_count=0,
        recent_replay_detected=False,
        impossible_travel=False,
        behavior_anomaly=False,
    )

    result = TrustEvaluator.evaluate(context)

    assert result.score == (
        ATTESTATION_VERIFIED_BONUS
        + LOW_CREDENTIAL_COUNT_BONUS
        + KNOWN_DEVICE_BONUS
    )

    assert "Hardware-backed credential" not in result.reasons
    assert "Attestation verified" in result.reasons
    
def test_attestation_with_multiple_credentials():

    context = DeviceTrustContext(
        device=make_device(
            hardware_backed=True,
            attestation_verified=True,
        ),
        credential_count=2,      # <-- important
        session_count=1,
        failed_auth_count=0,
        recent_replay_detected=False,
        impossible_travel=False,
        behavior_anomaly=False,
    )

    result = TrustEvaluator.evaluate(context)

    assert "Attestation verified" in result.reasons

    # LOW_CREDENTIAL_COUNT_BONUS should NOT be applied.
    assert result.score == (
        HARDWARE_BACKED_BONUS
        + ATTESTATION_VERIFIED_BONUS
        + KNOWN_DEVICE_BONUS
    )
    
def test_device_without_attestation():

    context = DeviceTrustContext(
        device=make_device(
            attestation_verified=False,
        ),
        credential_count=1,
        session_count=1,
        failed_auth_count=0,
        recent_replay_detected=False,
        impossible_travel=False,
        behavior_anomaly=False,
    )

    assert context.device.attestation_verified is False

    result = TrustEvaluator.evaluate(context)

    assert result.score == (
        HARDWARE_BACKED_BONUS
        + LOW_CREDENTIAL_COUNT_BONUS
        + KNOWN_DEVICE_BONUS
    )

    assert "Attestation verified" not in result.reasons
    