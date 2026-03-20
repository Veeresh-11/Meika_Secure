import pytest
pytestmark = pytest.mark.track_a
from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.errors import SecurityPipelineError
from app.security.results import DenyReason


def test_clone_beats_all_other_device_failures():
    ctx = SecurityContext.fake_device(
        clone_confirmed=True,
        compromised=True,
        state="revoked",
    )

    pipeline = SecurityPipeline()

    with pytest.raises(SecurityPipelineError) as exc:
        pipeline.evaluate(ctx)

    assert exc.value.reason == DenyReason.DEVICE_CLONED
