import pytest

pytestmark = pytest.mark.track_a

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext


def test_deny_evidence_is_structured_and_auditable():
    pipeline = SecurityPipeline()
    ctx = SecurityContext.fake_deny_context()

    decision = pipeline.evaluate(ctx)

    evidence = decision.obligations["evidence"]

    assert isinstance(evidence, dict)
    assert "reason" in evidence
    assert "context_hash" in evidence
    assert "timestamp" in evidence
