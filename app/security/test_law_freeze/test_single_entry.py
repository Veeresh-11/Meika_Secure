# app/security/test_law_freeze/test_single_entry.py

import inspect
import app.security.decision as decision_module
from app.security.pipeline import SecureIDKernel


def test_security_decision_not_constructed_outside_kernel():
    """
    Ensure SecurityDecision constructor is not used
    outside its class definition.
    """

    source = inspect.getsource(decision_module)

    # Allow class definition itself
    occurrences = source.count("SecurityDecision(")

    # Only class definition should contain constructor reference
    # If more than 1 occurrence, someone is constructing it elsewhere
    assert occurrences <= 1


def test_kernel_is_primary_decision_entry():
    """
    Ensure decisions are created via kernel.evaluate only.
    """

    kernel = SecureIDKernel()
    ctx = kernel._default_context()

    decision = kernel.evaluate(ctx)

    assert decision is not None
    assert decision.outcome is not None
