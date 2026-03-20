# app/security/test_kernel_determinism_contract.py
import pytest

pytestmark = [
    pytest.mark.track_b,
    pytest.mark.kernel,
]

from app.security.pipeline import SecureIDKernel
from app.security.context import SecurityContext


def test_kernel_is_decision_deterministic():
    kernel = SecureIDKernel()
    ctx = SecurityContext.fake_allow_context()

    d1 = kernel.evaluate(ctx)
    d2 = kernel.evaluate(ctx)

    assert d1.outcome == d2.outcome
    assert d1.reason == d2.reason
