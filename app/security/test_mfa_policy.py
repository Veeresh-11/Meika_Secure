from types import SimpleNamespace

from app.security.adaptive.mfa_policy import MFAPolicy


def test_allow_returns_none():
    policy = MFAPolicy()

    result = policy.challenge_for(
        SimpleNamespace(action="ALLOW")
    )

    assert result is None


def test_mfa_required_returns_totp():
    policy = MFAPolicy()

    result = policy.challenge_for(
        SimpleNamespace(action="MFA_REQUIRED")
    )

    assert result == "TOTP"


def test_deny_returns_none():
    policy = MFAPolicy()

    result = policy.challenge_for(
        SimpleNamespace(action="DENY")
    )

    assert result is None


def test_unknown_action_returns_none():
    policy = MFAPolicy()

    result = policy.challenge_for(
        SimpleNamespace(action="SOMETHING_ELSE")
    )

    assert result is None