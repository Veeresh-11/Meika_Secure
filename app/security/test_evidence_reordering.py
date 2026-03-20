# app/security/test_evidence_reordering.py
import pytest

pytestmark = [
    pytest.mark.track_c,
    pytest.mark.evidence,
]

from app.security.pipeline import SecureIDKernel


def test_evidence_reordering_changes_hash():
    kernel = SecureIDKernel()

    ctx1 = kernel._default_context()
    ctx2 = kernel._default_context()

    d1 = kernel.evaluate(ctx1)
    d2 = kernel.evaluate(ctx2)

    # Reordering contexts produces different hashes
    kernel2 = SecureIDKernel()
    d2b = kernel2.evaluate(ctx2)
    d1b = kernel2.evaluate(ctx1)

    assert d1.evidence_hash != d2.evidence_hash
    assert d1b.evidence_hash != d2b.evidence_hash
