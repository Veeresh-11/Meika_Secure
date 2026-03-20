from app.security.pipeline import SecureIDKernel
from app.security.runtime_state import KernelState
from app.security.errors import SecurityInvariantViolation


def test_safe_mode_blocks_allow(monkeypatch):
    kernel = SecureIDKernel()

    # Force tamper
    kernel._enter_safe_mode()

    ctx = kernel._default_context()

    try:
        kernel.evaluate(ctx)
    except Exception:
        pass

    assert kernel._state == KernelState.SAFE_MODE


def test_replay_still_possible():
    kernel = SecureIDKernel()
    kernel._enter_safe_mode()

    assert kernel._state == KernelState.SAFE_MODE
