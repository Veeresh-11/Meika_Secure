from app.security.adaptive.risk_score import calculate_risk_score
from app.security.adaptive.risk_signals import RiskSignals


def test_new_device_increases_risk():
    score, _ = calculate_risk_score(
        RiskSignals(new_device=True)
    )

    assert score > 0


def test_tor_is_high_risk():
    score, _ = calculate_risk_score(
        RiskSignals(tor_detected=True)
    )

    assert score >= 50


def test_failed_logins_increase_score():
    score, _ = calculate_risk_score(
        RiskSignals(failed_login_count=5)
    )

    assert score > 0