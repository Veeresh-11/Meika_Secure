from typing import Dict
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
        """
        Evaluate policy rule conditions against context.
        
        Supports AND/OR logic:
        - "all" (AND): All conditions must match
        - "any" (OR): At least one condition must match
        """
        if not rule.when:
            # No conditions = always match
            return True
        
        conditions = rule.when.get("conditions", [])
        logic = rule.when.get("logic", "all")  # Default: AND logic
        
        if not conditions:
            # No conditions specified = match
            return True
        
        # Evaluate all conditions
        results = [self._evaluate_condition(cond, ctx) for cond in conditions]
        
        # Apply logic
        if logic == "all":
            # AND: all must be True
            return all(results)
        elif logic == "any":
            # OR: at least one must be True
            return any(results)
        else:
            # Unknown logic, default to allow (fail open)
            return True
    
    def _evaluate_condition(self, condition: Dict, ctx: SecurityContext) -> bool:
        """Evaluate a single policy condition against context."""
        
        cond_type = condition.get("type")
        
        if cond_type == "user":
            # Match principal ID
            expected = condition.get("value")
            return ctx.principal_id == expected
        
        elif cond_type == "group":
            # Match principal's group membership
            # For now, check metadata for group_membership
            user_groups = ctx.metadata.get("groups", [])
            expected_group = condition.get("value")
            return expected_group in user_groups
        
        elif cond_type == "device_posture":
            # Check device posture level
            if ctx.device is None:
                return False
            
            actual_posture = getattr(ctx.device, "posture", "unknown")
            required_posture = condition.get("required_level", "any")
            
            # Posture levels (restrictive: can only deny)
            posture_hierarchy = {
                "revoked": 0,
                "degraded": 1,
                "observed": 2,
                "known": 3,
                "trusted": 4,
            }
            
            actual_level = posture_hierarchy.get(actual_posture, 0)
            required_level = posture_hierarchy.get(required_posture, 0)
            
            # Higher posture is better
            return actual_level >= required_level
        
        elif cond_type == "mfa_age_hours":
            # Check MFA timestamp
            if ctx.device is None:
                return False
            
            last_mfa = getattr(ctx.device, "last_mfa_at", None)
            max_hours = condition.get("max_hours", 24)
            
            if last_mfa is None:
                return False
            
            from datetime import datetime, timedelta
            age = (ctx.request_time - last_mfa).total_seconds() / 3600
            return age <= max_hours
        
        elif cond_type == "time_of_day":
            # Check request time is within allowed hours
            current_hour = ctx.request_time.hour
            allowed_hours = condition.get("allowed_hours", list(range(24)))
            return current_hour in allowed_hours
        
        elif cond_type == "location":
            # Check request location against allowed geos
            request_geo = ctx.metadata.get("geo_location", "unknown")
            allowed_geos = condition.get("allowed_geos", [])
            return request_geo in allowed_geos
        
        elif cond_type == "intent":
            # Match on the action/intent
            allowed_intents = condition.get("allowed", [])
            denied_intents = condition.get("denied", [])
            
            if denied_intents and ctx.intent in denied_intents:
                return False
            
            if allowed_intents and ctx.intent not in allowed_intents:
                return False
            
            return True
        
        elif cond_type == "authenticated":
            # Check if user is authenticated
            required = condition.get("required", True)
            return ctx.authenticated == required
        
        else:
            # Unknown condition type, fail closed (deny)
            return False