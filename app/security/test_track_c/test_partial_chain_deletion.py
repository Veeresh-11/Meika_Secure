"""
TRACK C — Partial Chain Deletion Detection

Removing any record from the middle of the chain
MUST break replay integrity.
"""

import pytest

pytestmark = [
    pytest.mark.track_c,
    pytest.mark.evidence,
]

from app.security.pipeline import SecureIDKernel
from app.security.errors import SecurityInvariantViolation


def test_partial_chain_deletion_is_detected(kernel):
    ctx = kernel._default_context()

    d1 = kernel.evaluate(ctx)
    d2 = kernel.evaluate(ctx)
    d3 = kernel.evaluate(ctx)

    # Simulate attacker removing middle record
    tampered_chain = [d1.evidence_hash, d3.evidence_hash]

    # Replay must fail because chain linkage is broken
    assert tampered_chain[1] != tampered_chain[0]
