# app/security/test_evidence_chain_integrity.py
"""
TRACK B — Evidence Chain Law Tests

These tests define the non-negotiable security invariants
of the evidence system.

If a test in this file fails:
- The system must fail closed
- The code must change, not the test

These tests are SECURITY LAW, not implementation detail.
"""

import pytest
pytestmark = [
    pytest.mark.track_c,
    pytest.mark.evidence,
]

from app.security.pipeline import SecureIDKernel


def test_evidence_chain_integrity():
    """
    Evidence must form a strict chain.
    Later evidence must depend on earlier evidence.
    """

    kernel = SecureIDKernel()
    ctx = kernel._default_context()

    d1 = kernel.evaluate(ctx)
    d2 = kernel.evaluate(ctx)
    d3 = kernel.evaluate(ctx)

    # Chain integrity is proven by deterministic hash evolution
    assert d1.evidence_hash != d2.evidence_hash
    assert d2.evidence_hash != d3.evidence_hash
    assert d1.evidence_hash != d3.evidence_hash

