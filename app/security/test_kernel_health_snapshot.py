import pytest
from app.security.pipeline import SecureIDKernel
from app.security.context import SecurityContext
from datetime import datetime


def test_health_snapshot_normal_state():
    kernel = SecureIDKernel()
    snapshot = kernel.health_snapshot()

    assert snapshot["state"] == "NORMAL"
    assert snapshot["kernel_version"] is not None
    assert snapshot["build_hash"] is not None
    assert snapshot["safe_mode_reason"] is None


def test_health_snapshot_after_allow():
    kernel = SecureIDKernel()

    ctx = kernel._default_context()
    kernel.evaluate(ctx)

    snapshot = kernel.health_snapshot()

    assert snapshot["last_sequence_number"] == 0
    assert snapshot["last_record_hash"] is not None


def test_health_snapshot_after_safe_mode():
    kernel = SecureIDKernel()

    kernel._enter_safe_mode("TEST_REASON")
    snapshot = kernel.health_snapshot()

    assert snapshot["state"] == "SAFE_MODE"
    assert snapshot["safe_mode_reason"] == "TEST_REASON"


def test_health_snapshot_never_raises():
    kernel = SecureIDKernel()

    for _ in range(5):
        snapshot = kernel.health_snapshot()
        assert isinstance(snapshot, dict)
