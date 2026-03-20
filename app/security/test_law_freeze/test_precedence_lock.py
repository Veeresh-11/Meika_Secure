# app/security/test_law_freeze/test_precedence_lock.py

from app.security.pipeline import SecureIDKernel


class ExplodingPolicy:
    def evaluate(self, ctx):
        raise Exception("Policy executed unexpectedly")


def test_policy_not_called_after_device_fail():
    """
    If device fails, policy must never execute.
    """

    kernel = SecureIDKernel()
    kernel.policy = ExplodingPolicy()

    ctx = kernel._default_context()
    ctx = ctx.fake_device(clone_confirmed=True)

    decision = kernel.evaluate(ctx)

    assert decision.outcome.name == "DENY"
