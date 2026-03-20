from app.security.context import SecurityContext


def build_test_context(
    *,
    subject_id="test-user",
    resource_id="test-resource",
    action="access",
    device=None,
    evidence=None,
    risk=None,
):
    """
    Canonical test context builder.
    Matches CURRENT SecurityContext signature.
    """
    return SecurityContext(
        subject_id=subject_id,
        resource_id=resource_id,
        action=action,
        device=device,
        evidence=evidence,
        risk=risk,
    )
