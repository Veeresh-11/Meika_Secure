import pytest
from datetime import datetime, timedelta

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.grants.models import Grant


@pytest.fixture
def expired_grant():
    return Grant(
        grant_id="g1",
        principal_id="u",
        expires_at=datetime.utcnow() - timedelta(seconds=1),
        issued_by_policy="test_policy",
        justification="expired_grant_test",
        intent="authentication.attempt",
        issued_at=datetime.utcnow(),
    )


@pytest.fixture
def pipeline():
    return SecurityPipeline(
        policy_evaluator=lambda ctx: None
    )


@pytest.fixture
def context():
    return SecurityContext(
        request_id="req-1",
        principal_id="u",
        intent="auth",
        authenticated=True,
        device_id=None,
        device=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )
