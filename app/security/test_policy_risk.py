from types import SimpleNamespace

from app.security.policy.evaluators.risk import (
    match_risk,
)


def test_no_risk_rule():
    rule = SimpleNamespace(when={})

    ctx = SimpleNamespace(
        risk_signals={}
    )

    assert match_risk(rule, ctx) is True


def test_risk_below_threshold():
    rule = SimpleNamespace(
        when={"max_risk_score": 50}
    )

    ctx = SimpleNamespace(
        risk_signals={"score": 20}
    )

    assert match_risk(rule, ctx) is True


def test_risk_equal_threshold():
    rule = SimpleNamespace(
        when={"max_risk_score": 50}
    )

    ctx = SimpleNamespace(
        risk_signals={"score": 50}
    )

    assert match_risk(rule, ctx) is True


def test_risk_above_threshold():
    rule = SimpleNamespace(
        when={"max_risk_score": 50}
    )

    ctx = SimpleNamespace(
        risk_signals={"score": 80}
    )

    assert match_risk(rule, ctx) is False


def test_risk_missing_score():
    rule = SimpleNamespace(
        when={"max_risk_score": 50}
    )

    ctx = SimpleNamespace(
        risk_signals={}
    )

    assert match_risk(rule, ctx) is False