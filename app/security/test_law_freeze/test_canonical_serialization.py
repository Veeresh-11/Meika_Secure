# app/security/test_law_freeze/test_canonical_serialization.py

import json
from app.security.pipeline import SecureIDKernel


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def test_decision_serialization_deterministic():
    """
    Same input must yield identical serialized output.
    """

    kernel = SecureIDKernel()
    ctx = kernel._default_context()

    d1 = kernel.evaluate(ctx)
    d2 = kernel.evaluate(ctx)

    s1 = canonical_json(d1.to_deterministic_dict())
    s2 = canonical_json(d2.to_deterministic_dict())

    assert s1 == s2
