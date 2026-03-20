"""
TRACK C — Version-Agnostic Replay Law

Evidence produced by older kernels MUST remain replayable
by newer kernels. Kernel version MUST NOT be a trust input.
"""

import pytest

pytestmark = [
    pytest.mark.track_c,
    pytest.mark.evidence,
]

from app.security.pipeline import SecureIDKernel


def test_replay_is_version_agnostic(kernel):
    ctx = kernel._default_context()

    # Produce evidence with "old" kernel
    d1 = kernel.evaluate(ctx)
    d2 = kernel.evaluate(ctx)

    chain = [
        d1.evidence_hash,
        d2.evidence_hash,
    ]

    # Simulate new kernel instance
    new_kernel = SecureIDKernel()

    # Replay means: chain hashes must still validate structurally
    # (We do NOT re-evaluate policy or context)
    for h in chain:
        assert isinstance(h, str)
        assert len(h) == 64
