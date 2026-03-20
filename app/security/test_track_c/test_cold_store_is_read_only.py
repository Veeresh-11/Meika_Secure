import pytest
from app.security.evidence.memory.cold import ColdEvidenceStore

def test_cold_store_has_no_write_methods():
    store = ColdEvidenceStore(reader=None)

    forbidden = ["append", "delete", "update", "rewrite"]
    for method in forbidden:
        assert not hasattr(store, method)
