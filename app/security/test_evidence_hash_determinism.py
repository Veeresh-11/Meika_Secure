# app/security/test_evidence_hash_determinism.py
import pytest

pytestmark = [
    pytest.mark.track_c,
    pytest.mark.evidence,
]

from app.security.pipeline import SecureIDKernel


def test_evidence_hash_is_deterministic_for_same_context():
    kernel = SecureIDKernel()
    ctx = kernel._default_context()

    d1 = kernel.evaluate(ctx)

    # New kernel instance → same context → same first hash
    kernel2 = SecureIDKernel()
    d2 = kernel2.evaluate(ctx)

    assert d1.evidence_hash == d2.evidence_hash
