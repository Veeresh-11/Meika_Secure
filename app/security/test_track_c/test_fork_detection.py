"""
TRACK C — Fork Detection Law (Corrected)

Forks are detected ONLY when histories diverge in
content or ordering — not by kernel identity.
"""

import pytest

pytestmark = [
    pytest.mark.track_c,
    pytest.mark.evidence,
]

from app.security.pipeline import SecureIDKernel


def test_forked_histories_are_detectable():
    kernel_a = SecureIDKernel()
    kernel_b = SecureIDKernel()

    ctx1 = kernel_a._default_context()
    ctx2 = kernel_a._default_context()

    # Kernel A: ctx1 → ctx2
    a1 = kernel_a.evaluate(ctx1)
    a2 = kernel_a.evaluate(ctx2)

    # Kernel B: ctx2 → ctx1 (order changed = fork)
    b1 = kernel_b.evaluate(ctx2)
    b2 = kernel_b.evaluate(ctx1)

    # Genesis may match
    assert a1.evidence_hash != a2.evidence_hash

    # Fork MUST be detectable
    assert a2.evidence_hash != b2.evidence_hash
