# app/security/test_law_freeze/test_fail_closed_evidence.py

from app.security.pipeline import SecureIDKernel


class FailingStore:
    def append(self, record):
        raise Exception("Simulated failure")


def test_allow_fails_if_evidence_write_fails():
    """
    ALLOW must never exit kernel without evidence commit.
    """

    kernel = SecureIDKernel()
    kernel.evidence_store = FailingStore()

    ctx = kernel._default_context()

    decision = kernel.evaluate(ctx)

    assert decision.outcome.name == "DENY"
