from app.security.pipeline import SecureIDKernel
from app.security.recovery import (
    export_evidence_store,
    verify_store_integrity,
)
from app.security.evidence.store import InMemoryEvidenceStore


def test_partial_chain_detection():

    kernel = SecureIDKernel()

    for _ in range(5):
        kernel.evaluate(kernel._default_context())

    records = export_evidence_store(kernel.evidence_store)

    # simulate truncated restore
    truncated = records[:-1]

    new_store = InMemoryEvidenceStore()

    for r in truncated:
        new_store.append(r)

    assert verify_store_integrity(new_store)
