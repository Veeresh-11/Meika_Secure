import pytest
pytestmark = pytest.mark.track_a
from datetime import datetime, timedelta
from app.security.context import SecurityContext
from app.security.errors import SecurityPipelineError

def test_expired_grant_is_hard_stop(expired_grant, pipeline, context):
    ctx = SecurityContext(
        **{**context.__dict__, "grant": expired_grant}
    )

    with pytest.raises(SecurityPipelineError):
        pipeline.evaluate(ctx)

