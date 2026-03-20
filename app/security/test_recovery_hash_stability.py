from app.security.pipeline import SecureIDKernel
from app.security.recovery import (
    export_evidence_store,
    compute_export_hash,
)


def test_export_hash_is_stable():

    kernel = SecureIDKernel()

    for _ in range(3):
        kernel.evaluate(kernel._default_context())

    records1 = export_evidence_store(kernel.evidence_store)
    hash1 = compute_export_hash(records1)

    records2 = export_evidence_store(kernel.evidence_store)
    hash2 = compute_export_hash(records2)

    assert hash1 == hash2
