import hashlib
from app.security.results import DenyReason

def test_deny_reason_hash_frozen():
    values = sorted([r.name + ":" + r.value for r in DenyReason])
    digest = hashlib.sha256("|".join(values).encode()).hexdigest()

    # Run once to compute real value, then freeze it.
    assert digest == "bcad5e207ee1416dd978571bbbcc32bc82287135b3f56da488c0d2988acbef9a"

