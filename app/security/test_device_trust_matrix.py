import pytest

pytestmark = pytest.mark.track_a
from app.security.errors import SecurityPipelineError, FailureClass
from app.security.results import DenyReason
from app.security.pipeline import SecurityPipeline
from app.security.decision import DecisionOutcome
from app.security.context import SecurityContext

# Kernel is the only authority allowed to ALLOW
pipeline = SecurityPipeline()


def test_clone_beats_all_other_failures():
    ctx = SecurityContext.fake_device(
        clone_confirmed=True,
        compromised=True,
        registered=False,
        state="revoked",
        hardware_backed=False,
    )

    with pytest.raises(SecurityPipelineError) as exc:
        pipeline.evaluate(ctx)

    assert exc.value.reason == DenyReason.DEVICE_CLONED
    assert exc.value.failure_class == FailureClass.DEVICE


def test_revoked_beats_compromised():
    ctx = SecurityContext.fake_device(
        registered=True,
        state="revoked",
        compromised=True,
    )

    with pytest.raises(SecurityPipelineError) as exc:
        pipeline.evaluate(ctx)

    assert exc.value.reason == DenyReason.DEVICE_REVOKED
    assert exc.value.failure_class == FailureClass.DEVICE


def test_unregistered_beats_revoked():
    ctx = SecurityContext.fake_device(
        registered=False,
        state="revoked",
    )

    with pytest.raises(SecurityPipelineError) as exc:
        pipeline.evaluate(ctx)

    assert exc.value.reason == DenyReason.DEVICE_NOT_REGISTERED
    assert exc.value.failure_class == FailureClass.DEVICE


def test_good_device_allows_flow():
    ctx = SecurityContext.fake_device(
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

    decision = pipeline.evaluate(ctx)
    assert decision.outcome == DecisionOutcome.ALLOW
