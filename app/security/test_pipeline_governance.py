import pytest

from datetime import datetime
from dataclasses import replace

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.errors import SecurityPipelineError


class RevokedRegistry:

    def is_revoked(self, version):
        return True


def test_policy_revoked():

    pipeline = SecurityPipeline(
        revocation_registry=RevokedRegistry()
    )

    ctx = SecurityContext(
        request_id="1",
        principal_id="user",
        intent="authentication.attempt",
        authenticated=True,
        device=None,
        device_id=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
        grant=None,
    )

    with pytest.raises(SecurityPipelineError):
        pipeline.evaluate(ctx)