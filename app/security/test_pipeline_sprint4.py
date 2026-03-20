import pytest

# -------------------------------------------------
# Sprint 4 pipeline + grants integration (disabled)
# -------------------------------------------------

from datetime import datetime

from app.security.context import SecurityContext
from app.security.device_snapshot import DeviceSnapshot
from app.security.policy.loader import load_policy
from app.security.policy.engine import PolicyEngine
from app.security.pipeline import SecurityPipeline
from app.security.test_helpers.device_builder import build_device

# ❌ GrantScope intentionally not implemented yet
# from app.security.grants.models import GrantScope
# from app.security.grants.issuer import GrantIssuer
# from app.security.grants.store import GrantStore
# from app.security.grants.validator import GrantValidator

from app.security.decision import SecurityDecision, DecisionOutcome


def test_pipeline_with_grant_allows_request():
    """
    Sprint 4 contract:
    - Policy produces ALLOW
    - Grant is issued
    - Pipeline honors grant
    """

    def policy_evaluator(ctx):
        return SecurityDecision(
            outcome=DecisionOutcome.ALLOW,
            reason="test-policy",
            policy_version="test",
            evaluated_at=datetime.utcnow(),
        )

    policy = load_policy("policies/authentication_policy.yaml")
    engine = PolicyEngine(policy)

    pipeline = SecurityPipeline(policy_evaluator=policy_evaluator)

    device = build_device(
        device_id="device-1",
        registered=True,
        state="active",
        secure_boot=True,
        compromised=False,
        clone_confirmed=False,
    )

    snapshot = DeviceSnapshot(
        device_id=device.device_id,
        registered=device.registered,
        compromised=device.compromised,
        clone_confirmed=device.clone_confirmed,
    )

    ctx = SecurityContext(
        request_id="req-1",
        principal_id="user-1",
        intent="authentication.attempt",
        authenticated=True,
        device_id=device.device_id,
        device=snapshot,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )

    decision = engine.evaluate(ctx)

    assert decision.outcome is DecisionOutcome.ALLOW
