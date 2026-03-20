from app.security.context import SecurityContext
from app.security.decision import DecisionOutcome
from app.security.policy.models import PolicyDocument, PolicyRule
from app.security.results import PolicyResult, ResultKind


class PolicyEngine:
    """
    Sprint A2 policy engine.

    Enforces security precedence before policy rules.
    Supports optional graph authorization.
    """

    def __init__(self, policy: PolicyDocument, graph=None):
        self._policy = policy
        self._graph = graph

    def evaluate(self, ctx: SecurityContext) -> PolicyResult:

        device = ctx.device

        # ------------------------------------------------------------------
        # HARD PRECEDENCE (security invariants)
        # ------------------------------------------------------------------

        if device is not None:

            if getattr(device, "clone_confirmed", False):
                return PolicyResult(
                    outcome=DecisionOutcome.DENY,
                    policy_version=self._policy.version,
                    evaluated_at=ctx.request_time,
                    kind=ResultKind.POLICY,
                    reason="Device cloning detected",
                )

            if getattr(device, "compromised", False):
                return PolicyResult(
                    outcome=DecisionOutcome.DENY,
                    policy_version=self._policy.version,
                    evaluated_at=ctx.request_time,
                    kind=ResultKind.POLICY,
                    reason="Device compromised",
                )

        # ------------------------------------------------------------------
        # GRAPH AUTHORIZATION (optional)
        # ------------------------------------------------------------------

        if self._graph is not None:

            subject = ctx.principal_id
            action = ctx.intent
            resource = ctx.metadata.get("resource")

            if resource is not None:

                allowed = self._graph.check(subject, action, resource)

                if not allowed:
                    return PolicyResult(
                        outcome=DecisionOutcome.DENY,
                        policy_version=self._policy.version,
                        evaluated_at=ctx.request_time,
                        kind=ResultKind.POLICY,
                        reason="Graph authorization denied",
                    )

        # ------------------------------------------------------------------
        # YAML POLICY RULES
        # ------------------------------------------------------------------

        for rule in self._policy.rules:

            if self._matches(rule, ctx):

                return PolicyResult(
                    outcome=DecisionOutcome(rule.effect),
                    policy_version=self._policy.version,
                    evaluated_at=ctx.request_time,
                    kind=ResultKind.POLICY,
                    reason=rule.reason,
                )

        return PolicyResult(
            outcome=DecisionOutcome.DENY,
            policy_version=self._policy.version,
            evaluated_at=ctx.request_time,
            kind=ResultKind.POLICY,
            reason="No matching policy rule",
        )

    def _matches(self, rule: PolicyRule, ctx: SecurityContext) -> bool:
        # Sprint A2 structural matching
        return True