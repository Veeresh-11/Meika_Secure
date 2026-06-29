from datetime import datetime, timedelta
from dataclasses import replace
import pytest

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.errors import SecurityPipelineError


class Grant:

    def __init__(self, expires_at, intent):
        self.expires_at = expires_at
        self.intent = intent


def ctx():

    return SecurityContext(
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


def test_expired_grant():

    pipeline = SecurityPipeline()

    g = Grant(
        expires_at=datetime.utcnow() - timedelta(hours=1),
        intent="authentication.attempt",
    )

    with pytest.raises(SecurityPipelineError):
        pipeline.evaluate(
            replace(ctx(), grant=g)
        )


def test_scope_mismatch():

    pipeline = SecurityPipeline()

    g = Grant(
        expires_at=datetime.utcnow() + timedelta(hours=1),
        intent="admin.delete",
    )

    with pytest.raises(SecurityPipelineError):
        pipeline.evaluate(
            replace(ctx(), grant=g)
        )