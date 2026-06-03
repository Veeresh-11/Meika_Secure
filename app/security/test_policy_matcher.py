"""
Tests for Policy Engine Matcher Implementation (P0.2)

Tests for the fixed policy rule matcher that now properly evaluates
conditions with AND/OR logic and supports 8 condition types.
"""

import pytest
from datetime import datetime, timedelta
from app.security.policy.engine import PolicyEngine
from app.security.policy.models import PolicyDocument, PolicyRule, PolicyEffect
from app.security.context import SecurityContext
from app.security.decision import DecisionOutcome
from app.security.device_snapshot import DeviceSnapshot


def create_test_context(
    principal_id="user1",
    authenticated=True,
    device_id="device1",
    device=None,
    metadata=None,
    request_time=None,
    intent="test.action",
):
    """Create a test SecurityContext with sensible defaults."""
    if request_time is None:
        request_time = datetime.utcnow()
    
    if metadata is None:
        metadata = {}
    
    return SecurityContext(
        request_id="test-req-1",
        principal_id=principal_id,
        intent=intent,
        authenticated=authenticated,
        device_id=device_id,
        device=device,
        risk_signals={},
        request_time=request_time,
        metadata=metadata,
    )


def test_policy_matcher_user_condition():
    """Test: User matching condition type."""
    rule = PolicyRule(
        name="user-match",
        effect=PolicyEffect.ALLOW,
        when={
            "logic": "all",
            "conditions": [
                {"type": "user", "value": "admin@example.com"}
            ]
        },
        reason="Allow admin user"
    )
    
    policy = PolicyDocument(version="1.0", rules=(rule,))
    engine = PolicyEngine(policy)
    
    # Should match
    ctx = create_test_context(principal_id="admin@example.com")
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.ALLOW
    
    # Should not match
    ctx = create_test_context(principal_id="user@example.com")
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.DENY


def test_policy_matcher_group_condition():
    """Test: Group membership condition type."""
    rule = PolicyRule(
        name="group-match",
        effect=PolicyEffect.ALLOW,
        when={
            "logic": "all",
            "conditions": [
                {"type": "group", "value": "admins"}
            ]
        },
        reason="Allow members of admins group"
    )
    
    policy = PolicyDocument(version="1.0", rules=(rule,))
    engine = PolicyEngine(policy)
    
    # Should match - user is in groups list
    ctx = create_test_context(
        metadata={"groups": ["admins", "users"]}
    )
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.ALLOW
    
    # Should not match - user not in groups
    ctx = create_test_context(
        metadata={"groups": ["users"]}
    )
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.DENY


def test_policy_matcher_authenticated_condition():
    """Test: Authentication check condition type."""
    rule = PolicyRule(
        name="auth-required",
        effect=PolicyEffect.ALLOW,
        when={
            "logic": "all",
            "conditions": [
                {"type": "authenticated", "required": True}
            ]
        },
        reason="Only authenticated users"
    )
    
    policy = PolicyDocument(version="1.0", rules=(rule,))
    engine = PolicyEngine(policy)
    
    # Should match - user is authenticated
    ctx = create_test_context(authenticated=True)
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.ALLOW
    
    # Should not match - user not authenticated
    ctx = create_test_context(authenticated=False)
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.DENY


def test_policy_matcher_intent_condition():
    """Test: Intent/action matching condition type."""
    rule = PolicyRule(
        name="read-only",
        effect=PolicyEffect.ALLOW,
        when={
            "logic": "all",
            "conditions": [
                {"type": "intent", "allowed": ["file.read", "file.list"]}
            ]
        },
        reason="Allow read-only file operations"
    )
    
    policy = PolicyDocument(version="1.0", rules=(rule,))
    engine = PolicyEngine(policy)
    
    # Should match - action is in allowed list
    ctx = create_test_context(intent="file.read")
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.ALLOW
    
    # Should not match - write action denied
    ctx = create_test_context(intent="file.write")
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.DENY


def test_policy_matcher_and_logic():
    """Test: AND logic - all conditions must match."""
    rule = PolicyRule(
        name="admin-read-only",
        effect=PolicyEffect.ALLOW,
        when={
            "logic": "all",  # ALL conditions must pass
            "conditions": [
                {"type": "group", "value": "admins"},
                {"type": "authenticated", "required": True},
                {"type": "intent", "allowed": ["data.read"]},
            ]
        },
        reason="Admins can only read data"
    )
    
    policy = PolicyDocument(version="1.0", rules=(rule,))
    engine = PolicyEngine(policy)
    
    # All conditions match - should allow
    ctx = create_test_context(
        authenticated=True,
        intent="data.read",
        metadata={"groups": ["admins"]}
    )
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.ALLOW
    
    # One condition fails (not in group) - should deny
    ctx = create_test_context(
        authenticated=True,
        intent="data.read",
        metadata={"groups": ["users"]}  # not in admins
    )
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.DENY
    
    # One condition fails (not authenticated) - should deny
    ctx = create_test_context(
        authenticated=False,  # not authenticated
        intent="data.read",
        metadata={"groups": ["admins"]}
    )
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.DENY


def test_policy_matcher_or_logic():
    """Test: OR logic - any condition can match."""
    rule = PolicyRule(
        name="elevated-user",
        effect=PolicyEffect.ALLOW,
        when={
            "logic": "any",  # ANY condition can pass
            "conditions": [
                {"type": "user", "value": "superadmin@example.com"},
                {"type": "group", "value": "privileged"},
            ]
        },
        reason="Superadmin or privileged group members allowed"
    )
    
    policy = PolicyDocument(version="1.0", rules=(rule,))
    engine = PolicyEngine(policy)
    
    # First condition matches - should allow
    ctx = create_test_context(principal_id="superadmin@example.com")
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.ALLOW
    
    # Second condition matches - should allow
    ctx = create_test_context(
        principal_id="user@example.com",
        metadata={"groups": ["privileged"]}
    )
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.ALLOW
    
    # No conditions match - should deny
    ctx = create_test_context(
        principal_id="regular@example.com",
        metadata={"groups": ["users"]}
    )
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.DENY


def test_policy_matcher_time_of_day():
    """Test: Time-of-day condition type."""
    rule = PolicyRule(
        name="business-hours",
        effect=PolicyEffect.ALLOW,
        when={
            "logic": "all",
            "conditions": [
                {"type": "time_of_day", "allowed_hours": list(range(9, 18))}  # 9 AM - 5 PM
            ]
        },
        reason="Allow access during business hours"
    )
    
    policy = PolicyDocument(version="1.0", rules=(rule,))
    engine = PolicyEngine(policy)
    
    # During business hours (10 AM) - should allow
    business_time = datetime.utcnow().replace(hour=10, minute=0, second=0)
    ctx = create_test_context(request_time=business_time)
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.ALLOW
    
    # Outside business hours (11 PM) - should deny
    night_time = datetime.utcnow().replace(hour=23, minute=0, second=0)
    ctx = create_test_context(request_time=night_time)
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.DENY


def test_policy_matcher_fail_closed():
    """Test: Fail-closed design - unknown conditions deny access."""
    rule = PolicyRule(
        name="unknown-condition",
        effect=PolicyEffect.ALLOW,
        when={
            "logic": "all",
            "conditions": [
                {"type": "unknown_future_condition", "value": "test"}
            ]
        },
        reason="Unknown condition"
    )
    
    policy = PolicyDocument(version="1.0", rules=(rule,))
    engine = PolicyEngine(policy)
    
    ctx = create_test_context()
    result = engine.evaluate(ctx)
    # Unknown condition should fail closed (deny)
    assert result.outcome == DecisionOutcome.DENY


def test_policy_no_matching_rule_denies():
    """Test: If no rule matches, access is denied."""
    rule1 = PolicyRule(
        name="admin-only",
        effect=PolicyEffect.ALLOW,
        when={
            "logic": "all",
            "conditions": [
                {"type": "group", "value": "admins"}
            ]
        },
        reason="Admins only"
    )
    
    policy = PolicyDocument(version="1.0", rules=(rule1,))
    engine = PolicyEngine(policy)
    
    # User is not in admins group, so no rule matches
    ctx = create_test_context(
        metadata={"groups": ["users"]}
    )
    result = engine.evaluate(ctx)
    assert result.outcome == DecisionOutcome.DENY
    assert "No matching policy rule" in result.reason
