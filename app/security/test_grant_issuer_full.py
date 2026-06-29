from datetime import datetime

import pytest

from app.security.context import SecurityContext
from app.security.decision import (
    SecurityDecisionFactory,
    DecisionOutcome,
)
from app.security.grants.issuer import (
    GrantIssuer,
    GrantIssuanceError,
)


def allow_decision():
    return SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.ALLOW,
        reason="ok",
        policy_version="v1",
        evaluated_at=datetime.utcnow(),
        obligations={},
    )


def test_issue_requires_principal():

    issuer = GrantIssuer()

    ctx = SecurityContext(
        request_id="1",
        principal_id="",
        intent="authentication.attempt",
        authenticated=True,
        device_id=None,
        device=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
        grant=None,
    )

    with pytest.raises(
        GrantIssuanceError,
        match="Cannot issue grant without principal",
    ):
        issuer.issue(
            ctx=ctx,
            decision=allow_decision(),
            intent=ctx.intent,
            requested_lifetime_seconds=60,
            justification="test",
        )


def test_issue_rejects_zero_lifetime():

    issuer = GrantIssuer()

    ctx = SecurityContext.fake_allow_context()

    with pytest.raises(
        GrantIssuanceError,
        match="Invalid grant lifetime",
    ):
        issuer.issue(
            ctx=ctx,
            decision=allow_decision(),
            intent=ctx.intent,
            requested_lifetime_seconds=0,
            justification="test",
        )