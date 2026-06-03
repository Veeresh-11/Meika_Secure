from .risk_signals import RiskSignals


WEIGHTS = {
    "new_device": 30,
    "vpn_detected": 25,
    "tor_detected": 50,
    "admin_request": 20,
}


def calculate_risk_score(signals: RiskSignals) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    if signals.new_device:
        score += WEIGHTS["new_device"]
        reasons.append("new_device")

    if signals.vpn_detected:
        score += WEIGHTS["vpn_detected"]
        reasons.append("vpn_detected")

    if signals.tor_detected:
        score += WEIGHTS["tor_detected"]
        reasons.append("tor_detected")

    if signals.admin_request:
        score += WEIGHTS["admin_request"]
        reasons.append("admin_request")

    if signals.failed_login_count > 0:
        login_risk = min(signals.failed_login_count * 5, 30)
        score += login_risk
        reasons.append("failed_login_count")

    return min(score, 100), reasons