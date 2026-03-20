# app/security/test_evidence_atomicity.py
import pytest

pytestmark = [
    pytest.mark.track_b,
    pytest.mark.evidence,
]
from app.security.pipeline import SecureIDKernel
from app.security.errors import SecurityInvariantViolation
from app.security.context import SecurityContext


class PartialEvidenceEngine:
    """
    Simulates a broken evidence engine that writes but fails mid-commit.
    """

    def build_evidence_record(self, *args, **kwargs):
        return {"hash": "partial-hash"}

    def append_evidence_record(self, *args, **kwargs):
        # Simulate partial failure AFTER write
        return None


def test_partial_evidence_commit_fails_closed(monkeypatch):
    kernel = SecureIDKernel()

    # Inject broken engine
    monkeypatch.setattr(
        "app.security.pipeline.evidence_engine",
        PartialEvidenceEngine(),
    )

    ctx = SecurityContext.fake_allow_context()

    with pytest.raises(SecurityInvariantViolation):
        kernel.evaluate(ctx)
