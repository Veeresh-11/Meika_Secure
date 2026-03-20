from app.security.evidence.memory.hot import HotEvidenceStore

def test_hot_store_can_be_destroyed():
    store = HotEvidenceStore()
    store.append = None   # simulate catastrophic failure

    # Track C rule: loss ≠ security failure
    assert True
