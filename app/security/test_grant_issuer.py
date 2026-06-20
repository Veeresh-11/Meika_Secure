from datetime import datetime

import pytest

from app.security.context import SecurityContext
from app.security.decision import (
    DecisionOutcome,
    SecurityDecisionFactory,
)
from app.security.grants.issuer import (
    GrantIssuer,
    GrantIssuanceError,
)


def make_context():
    return SecurityContext(
        request_id="req1",
        principal_id="user1",
        intent="authentication.attempt",
        authenticated=True,
        device_id=None,
        device=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )


def allow_decision():
    return SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.ALLOW,
        reason="allowed",
        policy_version="v1",
        evaluated_at=datetime.utcnow(),
    )


def deny_decision():
    return SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.DENY,
        reason="denied",
        policy_version="v1",
        evaluated_at=datetime.utcnow(),
    )


def test_issue_grant():
    issuer = GrantIssuer()

    grant = issuer.issue(
        ctx=make_context(),
        decision=allow_decision(),
        intent="authentication.attempt",
        requested_lifetime_seconds=300,
        justification="test",
    )

    assert grant.principal_id == "user1"


def test_deny_decision_rejected():
    issuer = GrantIssuer()

    with pytest.raises(GrantIssuanceError):
        issuer.issue(
            ctx=make_context(),
            decision=deny_decision(),
            intent="authentication.attempt",
            requested_lifetime_seconds=300,
            justification="test",
        )


def test_empty_justification():
    issuer = GrantIssuer()

    with pytest.raises(GrantIssuanceError):
        issuer.issue(
            ctx=make_context(),
            decision=allow_decision(),
            intent="authentication.attempt",
            requested_lifetime_seconds=300,
            justification="",
        )


def test_intent_mismatch():
    issuer = GrantIssuer()

    with pytest.raises(GrantIssuanceError):
        issuer.issue(
            ctx=make_context(),
            decision=allow_decision(),
            intent="different.intent",
            requested_lifetime_seconds=300,
            justification="test",
        )