from .risk_decision import RiskDecision


class MFAPolicy:

    def challenge_for(self, decision: RiskDecision) -> str | None:

        if decision.action == "ALLOW":
            return None

        if decision.action == "MFA_REQUIRED":
            return "TOTP"

        if decision.action == "DENY":
            return None

        return None