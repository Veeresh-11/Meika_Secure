import pytest

pytestmark = pytest.mark.track_a
from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext


def test_deny_decision_is_evidenced():
    pipeline = SecurityPipeline()   # 👈 NOT SecureIDKernel

    ctx = SecurityContext.fake_deny_context()

    decision = pipeline.evaluate(ctx)

    assert decision.outcome.value == "deny"
    assert decision.obligations is not None
