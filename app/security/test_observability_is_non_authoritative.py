import pytest

pytestmark = [
    pytest.mark.track_a,
    pytest.mark.track_b,
]

from app.security.pipeline import SecureIDKernel
from app.security.context import SecurityContext


class ExplodingEmitter:
    def emit(self, *_):
        raise RuntimeError("SIEM down")


def test_observability_failure_does_not_block_decision():
    kernel = SecureIDKernel(event_emitter=ExplodingEmitter())

    ctx = SecurityContext.fake_allow_context()

    decision = kernel.evaluate(ctx)

    # Authorization must succeed even if observability fails
    assert decision.evidence_hash is not None
