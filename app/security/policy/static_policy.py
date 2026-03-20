# app/security/policy/static_policy.py

from app.security.policy.models import PolicyDocument, PolicyRule, PolicyEffect

STATIC_POLICY = PolicyDocument(
    version="A2-STATIC-1",
    rules=(
        PolicyRule(
            name="allow_authenticated",
            effect=PolicyEffect.ALLOW,
            when={"authenticated": True},
            reason="Authenticated principals are allowed",
        ),
    ),
)
