from app.security.adaptive.mfa_policy import MFAPolicy
from app.security.adaptive.risk_decision import RiskDecision


def test_allow_requires_no_mfa():

    policy = MFAPolicy()

    challenge = policy.challenge_for(
        RiskDecision(
            score=10,
            action="ALLOW",
            reasons=[],
        )
    )

    assert challenge is None


def test_medium_risk_requires_totp():

    policy = MFAPolicy()

    challenge = policy.challenge_for(
        RiskDecision(
            score=55,
            action="MFA_REQUIRED",
            reasons=["new_device"],
        )
    )

    assert challenge == "TOTP"