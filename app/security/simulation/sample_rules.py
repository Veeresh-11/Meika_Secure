from app.security.simulation.models import SimulationResult


def warn_grant_near_expiry(context, decision):
    grant = context.grant
    if not grant:
        return None

    remaining = (grant.expires_at - context.request_time).total_seconds()
    if remaining < 300:
        return SimulationResult(
            rule_id="grant.near.expiry",
            severity="WARN",
            message="Grant expires in under 5 minutes",
            metadata={"seconds_remaining": remaining},
        )
