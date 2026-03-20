# app/security/test_law_freeze/test_deny_reason_uniqueness_freeze.py

from app.security.pipeline import SecureIDKernel


def test_single_deny_reason_only():
    """
    Kernel must return exactly one deny reason.
    No stacking.
    """

    kernel = SecureIDKernel()
    ctx = kernel._default_context()

    # Trigger strongest device failure
    ctx = ctx.fake_device(clone_confirmed=True)

    decision = kernel.evaluate(ctx)

    assert decision.outcome.name == "DENY"
    assert decision.reason is not None
    assert not isinstance(decision.reason, list)
