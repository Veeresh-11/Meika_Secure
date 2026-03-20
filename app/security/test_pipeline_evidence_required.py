# app/security/test_pipeline_evidence_required.py

import pytest

pytestmark = [
    pytest.mark.track_b,
    pytest.mark.kernel,
]
from app.security.pipeline import SecureIDKernel
from app.security.context import SecurityContext
from app.security.errors import SecurityInvariantViolation


def test_allow_requires_evidence_commit(monkeypatch):
    """
    Kernel MUST fail closed if evidence cannot be committed.
    """

    kernel = SecureIDKernel()
    ctx = SecurityContext.fake_allow_context()

    # Force evidence commit to fail
    def broken_append(*args, **kwargs):
        return None

    monkeypatch.setattr(
        "app.security.evidence.engine.append_evidence_record",
        broken_append,
    )

    with pytest.raises(SecurityInvariantViolation):
        kernel.evaluate(ctx)
