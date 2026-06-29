from types import SimpleNamespace

from app.security.policy.evaluators.authentication import (
    match_authentication,
)


def test_no_authenticated_rule_matches():
    rule = SimpleNamespace(when={})
    ctx = SimpleNamespace(authenticated=True)

    assert match_authentication(rule, ctx) is True


def test_authenticated_true_matches():
    rule = SimpleNamespace(
        when={"authenticated": True}
    )

    ctx = SimpleNamespace(
        authenticated=True
    )

    assert match_authentication(rule, ctx) is True


def test_authenticated_true_fails():
    rule = SimpleNamespace(
        when={"authenticated": True}
    )

    ctx = SimpleNamespace(
        authenticated=False
    )

    assert match_authentication(rule, ctx) is False


def test_authenticated_false_matches():
    rule = SimpleNamespace(
        when={"authenticated": False}
    )

    ctx = SimpleNamespace(
        authenticated=False
    )

    assert match_authentication(rule, ctx) is True