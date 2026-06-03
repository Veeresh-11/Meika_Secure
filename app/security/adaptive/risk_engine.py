from .risk_score import calculate_risk_score
from .risk_signals import RiskSignals
from .risk_decision import RiskDecision


ALLOW = "ALLOW"
MFA_REQUIRED = "MFA_REQUIRED"
DENY = "DENY"


class RiskEngine:

    def evaluate(self, signals: RiskSignals) -> RiskDecision:

        score, reasons = calculate_risk_score(signals)

        if score < 30:
            action = ALLOW

        elif score <= 70:
            action = MFA_REQUIRED

        else:
            action = DENY

        return RiskDecision(
            score=score,
            action=action,
            reasons=reasons,
        )