# app/security/test_law_freeze/test_determinism_snapshot.py

import hashlib
import json
from app.security.pipeline import SecureIDKernel


EXPECTED_HASH = "4556821a457cc32852307aceec086acd315ff91906182190fbb822fb68118dfc"

def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def test_decision_hash_snapshot():
    """
    Freeze decision structure permanently.
    """

    kernel = SecureIDKernel()
    ctx = kernel._default_context()

    decision = kernel.evaluate(ctx)

    serialized = canonical_json(decision.to_deterministic_dict())
    digest = hashlib.sha256(serialized.encode()).hexdigest()

    if EXPECTED_HASH is None:
        print("FREEZE THIS HASH:", digest)
        assert False, "Replace EXPECTED_HASH with printed value"

    assert digest == EXPECTED_HASH
