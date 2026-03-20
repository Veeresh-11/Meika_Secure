# app/security/policy/evaluators/authentication.py

from app.security.context import SecurityContext
from app.security.policy.models import PolicyRule


def match_authentication(rule: PolicyRule, ctx: SecurityContext) -> bool:
    expected = rule.when.get("authenticated")
    if expected is None:
        return True
    return ctx.authenticated is expected

