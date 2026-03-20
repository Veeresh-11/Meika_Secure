# app/security/grants/issuer.py

from datetime import timedelta
from typing import Optional

from app.security.context import SecurityContext
from app.security.decision import SecurityDecision, DecisionOutcome
from app.security.grants.models import Grant, create_grant


class GrantIssuanceError(Exception):
    """Raised when a grant cannot be safely issued."""
    pass


class GrantIssuer:
    """
    Issues time-bound grants after a successful policy decision.
    """

    MAX_GRANT_LIFETIME_SECONDS = 900  # 15 minutes hard cap

    def issue(
        self,
        *,
        ctx: SecurityContext,
        decision: SecurityDecision,
        intent: str,
        requested_lifetime_seconds: int,
        justification: str,
    ) -> Grant:
        # 1️⃣ Policy must ALLOW
        if decision.outcome != DecisionOutcome.ALLOW:
            raise GrantIssuanceError("Grant issuance denied by policy decision")

        # 2️⃣ Principal must exist
        if not ctx.principal_id:
            raise GrantIssuanceError("Cannot issue grant without principal")

        # 3️⃣ Justification is mandatory
        if not justification or not justification.strip():
            raise GrantIssuanceError("Grant justification is required")

        # 4️⃣ Enforce lifetime bounds
        lifetime = min(
            requested_lifetime_seconds,
            self.MAX_GRANT_LIFETIME_SECONDS,
        )

        if lifetime <= 0:
            raise GrantIssuanceError("Invalid grant lifetime")

        # 5️⃣ Intent must match request
        if intent != ctx.intent:
            raise GrantIssuanceError(
                f"Grant intent '{intent}' does not match request intent '{ctx.intent}'"
            )

        # 6️⃣ Create grant
        return create_grant(
            principal_id=ctx.principal_id,
            intent=intent,
            lifetime_seconds=lifetime,
            issued_by_policy=decision.policy_version,
            justification=justification,
        )
