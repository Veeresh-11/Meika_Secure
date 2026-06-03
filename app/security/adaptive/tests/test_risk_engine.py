from app.security.adaptive import (
    RiskEngine,
    RiskSignals,
)


def test_allow_low_risk():

    engine = RiskEngine()

    result = engine.evaluate(
        RiskSignals()
    )

    assert result.action == "ALLOW"


def test_mfa_medium_risk():

    engine = RiskEngine()

    result = engine.evaluate(
        RiskSignals(
            new_device=True
        )
    )

    assert result.action == "MFA_REQUIRED"


def test_deny_high_risk():

    engine = RiskEngine()

    result = engine.evaluate(
        RiskSignals(
            tor_detected=True,
            vpn_detected=True,
            admin_request=True,
        )
    )

    assert result.action == "DENY"