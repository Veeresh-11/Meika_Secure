from types import SimpleNamespace
from datetime import datetime, timedelta

from app.security.policy.engine import PolicyEngine


def make_ctx():
    return SimpleNamespace(
        principal_id="alice",
        authenticated=True,
        intent="read",
        request_time=datetime.utcnow(),
        metadata={},
        device=None,
    )


def make_engine():
    return PolicyEngine(
        policy=SimpleNamespace(
            version="1.0",
            rules=[],
        )
    )


# --------------------------------------------------
# _matches()
# --------------------------------------------------

def test_matches_empty_when():
    engine = make_engine()
    rule = SimpleNamespace(when={})

    assert engine._matches(rule, make_ctx()) is True


def test_matches_empty_conditions():
    engine = make_engine()

    rule = SimpleNamespace(
        when={
            "logic": "all",
            "conditions": [],
        }
    )

    assert engine._matches(rule, make_ctx()) is True


def test_matches_any_logic():
    engine = make_engine()

    rule = SimpleNamespace(
        when={
            "logic": "any",
            "conditions": [
                {"type": "user", "value": "bob"},
                {"type": "user", "value": "alice"},
            ],
        }
    )

    assert engine._matches(rule, make_ctx()) is True


def test_matches_unknown_logic_defaults_true():
    engine = make_engine()

    rule = SimpleNamespace(
        when={
            "logic": "weird",
            "conditions": [
                {"type": "user", "value": "bob"},
            ],
        }
    )

    assert engine._matches(rule, make_ctx()) is True


# --------------------------------------------------
# group
# --------------------------------------------------

def test_group_match():
    ctx = make_ctx()
    ctx.metadata["groups"] = ["admins"]

    condition = {
        "type": "group",
        "value": "admins",
    }

    assert make_engine()._evaluate_condition(condition, ctx) is True


# --------------------------------------------------
# device posture
# --------------------------------------------------

def test_device_posture_missing_device():
    condition = {
        "type": "device_posture",
        "required_level": "trusted",
    }

    assert make_engine()._evaluate_condition(
        condition,
        make_ctx(),
    ) is False


def test_device_posture_success():
    ctx = make_ctx()

    ctx.device = SimpleNamespace(
        posture="trusted"
    )

    condition = {
        "type": "device_posture",
        "required_level": "known",
    }

    assert make_engine()._evaluate_condition(
        condition,
        ctx,
    ) is True


# --------------------------------------------------
# MFA age
# --------------------------------------------------

def test_mfa_age_missing_device():
    condition = {
        "type": "mfa_age_hours",
        "max_hours": 24,
    }

    assert make_engine()._evaluate_condition(
        condition,
        make_ctx(),
    ) is False


def test_mfa_age_no_timestamp():
    ctx = make_ctx()

    ctx.device = SimpleNamespace(
        last_mfa_at=None
    )

    condition = {
        "type": "mfa_age_hours",
        "max_hours": 24,
    }

    assert make_engine()._evaluate_condition(
        condition,
        ctx,
    ) is False


def test_mfa_age_valid():
    ctx = make_ctx()

    ctx.device = SimpleNamespace(
        last_mfa_at=datetime.utcnow() - timedelta(hours=2)
    )

    condition = {
        "type": "mfa_age_hours",
        "max_hours": 24,
    }

    assert make_engine()._evaluate_condition(
        condition,
        ctx,
    ) is True


# --------------------------------------------------
# location
# --------------------------------------------------

def test_location_match():
    ctx = make_ctx()

    ctx.metadata["geo_location"] = "IN"

    condition = {
        "type": "location",
        "allowed_geos": ["IN", "US"],
    }

    assert make_engine()._evaluate_condition(
        condition,
        ctx,
    ) is True


# --------------------------------------------------
# intent
# --------------------------------------------------

def test_intent_denied():
    ctx = make_ctx()
    ctx.intent = "delete"

    condition = {
        "type": "intent",
        "denied": ["delete"],
    }

    assert make_engine()._evaluate_condition(
        condition,
        ctx,
    ) is False


def test_intent_not_allowed():
    ctx = make_ctx()
    ctx.intent = "delete"

    condition = {
        "type": "intent",
        "allowed": ["read"],
    }

    assert make_engine()._evaluate_condition(
        condition,
        ctx,
    ) is False


# --------------------------------------------------
# authenticated
# --------------------------------------------------

def test_authenticated_match():
    condition = {
        "type": "authenticated",
        "required": True,
    }

    assert make_engine()._evaluate_condition(
        condition,
        make_ctx(),
    ) is True


# --------------------------------------------------
# unknown type
# --------------------------------------------------

def test_unknown_condition_type():
    condition = {
        "type": "something_unknown"
    }

    assert make_engine()._evaluate_condition(
        condition,
        make_ctx(),
    ) is False
    
def test_matches_all_logic():
    engine = make_engine()

    rule = SimpleNamespace(
        when={
            "logic": "all",
            "conditions": [
                {"type": "user", "value": "alice"},
                {"type": "authenticated", "required": True},
            ],
        }
    )

    assert engine._matches(rule, make_ctx()) is True


def test_time_of_day_match():
    ctx = make_ctx()

    condition = {
        "type": "time_of_day",
        "allowed_hours": [ctx.request_time.hour],
    }

    assert make_engine()._evaluate_condition(
        condition,
        ctx,
    ) is True


def test_intent_success():
    ctx = make_ctx()

    condition = {
        "type": "intent",
        "allowed": ["read"],
    }

    assert make_engine()._evaluate_condition(
        condition,
        ctx,
    ) is True