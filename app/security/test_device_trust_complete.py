# app/security/test_device_trust_complete.py

import pytest

from app.security.device_snapshot import DeviceSnapshot
from app.security.device_trust import DeviceTrustEvaluator
from app.security.errors import SecurityPipelineError


def good_device():
    return DeviceSnapshot(
        device_id="d1",
        registered=True,
        state="active",
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        secure_boot=True,
        replay_detected=False,
        compromised=False,
        clone_confirmed=False,
    )


def test_clone_confirmed():
    d = good_device()
    object.__setattr__(d, "clone_confirmed", True)

    with pytest.raises(SecurityPipelineError):
        DeviceTrustEvaluator.enforce(d)


def test_not_registered():
    d = good_device()
    object.__setattr__(d, "registered", False)

    with pytest.raises(SecurityPipelineError):
        DeviceTrustEvaluator.enforce(d)


@pytest.mark.parametrize("state", ["revoked", "lost"])
def test_revoked_or_lost(state):
    d = good_device()
    object.__setattr__(d, "state", state)

    with pytest.raises(SecurityPipelineError):
        DeviceTrustEvaluator.enforce(d)


def test_compromised():
    d = good_device()
    object.__setattr__(d, "compromised", True)

    with pytest.raises(SecurityPipelineError):
        DeviceTrustEvaluator.enforce(d)


def test_not_hardware_backed():
    d = good_device()
    object.__setattr__(d, "hardware_backed", False)

    with pytest.raises(SecurityPipelineError):
        DeviceTrustEvaluator.enforce(d)


def test_attestation_failed():
    d = good_device()
    object.__setattr__(d, "attestation_verified", False)

    with pytest.raises(SecurityPipelineError):
        DeviceTrustEvaluator.enforce(d)


def test_binding_invalid():
    d = good_device()
    object.__setattr__(d, "binding_valid", False)

    with pytest.raises(SecurityPipelineError):
        DeviceTrustEvaluator.enforce(d)


def test_replay_detected():
    d = good_device()
    object.__setattr__(d, "replay_detected", True)

    with pytest.raises(SecurityPipelineError):
        DeviceTrustEvaluator.enforce(d)


def test_success():
    DeviceTrustEvaluator.enforce(good_device())