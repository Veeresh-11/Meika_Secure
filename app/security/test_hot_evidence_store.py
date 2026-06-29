from app.security.evidence.memory.hot import HotEvidenceStore
from app.security.evidence.store import InMemoryEvidenceStore


def test_hot_store_is_inmemory_store():

    store = HotEvidenceStore()

    assert isinstance(
        store,
        InMemoryEvidenceStore,
    )


def test_hot_store_starts_empty():

    store = HotEvidenceStore()

    assert store.next_sequence() == 0
    assert store.last_hash() is None
    assert store.hashes() == []


def test_hot_store_has_append_method():

    store = HotEvidenceStore()

    assert callable(store.append)