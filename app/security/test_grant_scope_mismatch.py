# app/security/test_grant_scope_mismatch.py

import pytest
from datetime import datetime, timedelta, timezone
pytestmark = pytest.mark.track_a
from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.grants.models import Grant
from app.security.errors import SecurityPipelineError
from app.security.results import DenyReason


def test_grant_scope_mismatch_denies():
    grant = Grant(
        grant_id="grant-1",
        principal_id="user",
        intent="other.intent",
        issued_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1),
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5),
        issued_by_policy="test-policy",
        justification="scope mismatch test",
    )

    ctx = SecurityContext(
        request_id="req-1",
        principal_id="user",
        intent="authentication.attempt",
        authenticated=True,
        device_id=None,
        device=None,
        risk_signals={},
        request_time=datetime.now(timezone.utc).replace(tzinfo=None),
        metadata={},
        grant=grant,
    )

    pipeline = SecurityPipeline()

    with pytest.raises(SecurityPipelineError) as exc:
        pipeline.evaluate(ctx)

    assert exc.value.reason == DenyReason.GRANT_SCOPE_MISMATCH
