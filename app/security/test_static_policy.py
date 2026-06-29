from app.security.policy.static_policy import STATIC_POLICY
from app.security.policy.models import PolicyEffect


def test_static_policy_version():

    assert STATIC_POLICY.version == "A2-STATIC-1"


def test_static_policy_has_one_rule():

    assert len(STATIC_POLICY.rules) == 1


def test_static_rule_contents():

    rule = STATIC_POLICY.rules[0]

    assert rule.name == "allow_authenticated"
    assert rule.effect == PolicyEffect.ALLOW
    assert rule.when == {"authenticated": True}
    assert "Authenticated principals" in rule.reason