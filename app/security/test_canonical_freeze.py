import hashlib
from app.security.canonical import canonical_json

def test_canonical_hash_stable():
    payload = {"b":2,"a":1}
    h = hashlib.sha256(canonical_json(payload)).hexdigest()

    assert h == "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
