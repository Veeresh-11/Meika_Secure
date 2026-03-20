import pytest

pytestmark = pytest.mark.track_a

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext


def test_deny_evidence_contains_reason_and_context():
    pipeline = SecurityPipeline()
    ctx = SecurityContext.fake_deny_context()

    decision = pipeline.evaluate(ctx)

    evidence = decision.obligations.get("evidence")

    assert evidence is not None
    assert "reason" in evidence
    assert "context_hash" in evidence
