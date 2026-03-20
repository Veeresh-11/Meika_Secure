# app/security/policy/evaluators/risk.py

from app.security.context import SecurityContext
from app.security.policy.models import PolicyRule


def match_risk(rule: PolicyRule, ctx: SecurityContext) -> bool:
    """
    Match risk-related conditions.
    Risk can RESTRICT or DENY, never ALLOW.
    """
    if "max_risk_score" in rule.when:
        score = ctx.risk_signals.get("score")
        if score is None or score > rule.when["max_risk_score"]:
            return False

    return True
