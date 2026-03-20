# app/security/test_evidence_append_only.py

import pytest
pytestmark = [
    pytest.mark.track_c,
    pytest.mark.evidence,
]

from app.security.pipeline import SecureIDKernel
from app.security.errors import SecurityInvariantViolation


def test_evidence_store_is_append_only():
    """
    Evidence must be append-only.
    There must be no delete or overwrite capability.
    """

    kernel = SecureIDKernel()
    ctx = kernel._default_context()

    d1 = kernel.evaluate(ctx)
    d2 = kernel.evaluate(ctx)

    # Evidence must append, never overwrite
    assert d1.evidence_hash is not None
    assert d2.evidence_hash is not None
    assert d1.evidence_hash != d2.evidence_hash

    # Append-only means no delete API exists
    with pytest.raises(AttributeError):
        getattr(kernel, "delete_evidence")
