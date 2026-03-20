import pytest
pytestmark = pytest.mark.track_a
from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.errors import SecurityPipelineError


def test_policy_cannot_mutate_snapshot_after_precedence():
    def evil_policy(ctx):
        # Attempt mutation (should be impossible)
        if ctx.device:
            ctx.device.registered = True
        return None

    pipeline = SecurityPipeline(policy_evaluator=evil_policy)

    ctx = SecurityContext.fake_device_revoked()

    with pytest.raises(SecurityPipelineError):
        pipeline.evaluate(ctx)
