import pytest
import time
from datetime import datetime
from dataclasses import replace
from app.security.context import SecurityContext
from app.security.policy.loader import load_policy
from app.security.policy.engine import PolicyEngine
from app.security.pipeline import SecurityPipelineError
from app.security.test_helpers.pipeline_builder import build_test_pipeline
pytestmark = pytest.mark.track_a
from app.security.grants.issuer import GrantIssuer
from app.security.grants.store import GrantStore
from app.security.grants.validator import GrantValidator


# Setup
policy = load_policy("policies/authentication_policy.yaml")
engine = PolicyEngine(policy)

grant_store = GrantStore()
grant_validator = GrantValidator(grant_store)
grant_issuer = GrantIssuer()

ctx = SecurityContext(
    request_id="req-expiry",
    principal_id="user-expiry",
    intent="authentication.attempt",
    authenticated=True,
    device_id=None,
    device=None,
    risk_signals={},
    request_time=datetime.utcnow(),
    metadata={},
)

decision = engine.evaluate(ctx)

grant = grant_issuer.issue(
    ctx=ctx,
    decision=decision,
    intent=ctx.intent,
    requested_lifetime_seconds=1,
    justification="Expiry test",
)


grant_store.add(grant)

time.sleep(2)

pipeline = build_test_pipeline(
    policy_evaluator=lambda ctx: decision,
    grant_validator=grant_validator,
)

try:
    # Attach grant to context (Sprint A3 contract)
    ctx_with_grant = replace(ctx, grant=grant)
    pipeline.evaluate(ctx_with_grant)
    print("❌ ERROR: expired grant was allowed")

except SecurityPipelineError as e:
    print("✅ Expected denial:", e)

