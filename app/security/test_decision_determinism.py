import pytest

pytestmark = pytest.mark.track_a

from app.security.pipeline import SecureIDKernel
from app.security.decision import DecisionOutcome
from app.security.test_helpers.context_factory import a1_test_context


def test_decision_is_deterministic():
    kernel = SecureIDKernel()
    ctx = a1_test_context()

    d1 = kernel.evaluate(ctx)
    d2 = kernel.evaluate(ctx)

    assert d1.outcome == d2.outcome
    assert d1.reason == d2.reason
