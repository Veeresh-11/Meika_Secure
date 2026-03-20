from app.security.pipeline import SecureIDKernel
from app.security.recovery import (
    export_evidence_store,
    restore_evidence_store,
    verify_store_integrity,
)
from app.security.evidence.store import InMemoryEvidenceStore


def test_export_and_restore_produces_identical_chain():

    kernel = SecureIDKernel()

    # create chain
    for _ in range(5):
        ctx = kernel._default_context()
        kernel.evaluate(ctx)

    original_store = kernel.evidence_store
    exported = export_evidence_store(original_store)

    new_store = InMemoryEvidenceStore()
    restore_evidence_store(new_store, exported)

    assert verify_store_integrity(new_store)
    assert new_store.next_sequence() == original_store.next_sequence()
