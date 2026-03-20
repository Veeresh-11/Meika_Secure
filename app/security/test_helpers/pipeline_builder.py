from app.security.pipeline import SecurityPipeline

def build_test_pipeline(
    *,
    policy_evaluator,
    **_ignored,   # swallow legacy args safely
):
    """
    Sprint A3-compatible test pipeline builder.
    Kernel owns grant enforcement & containment.
    """
    return SecurityPipeline(
        policy_evaluator=policy_evaluator
    )
