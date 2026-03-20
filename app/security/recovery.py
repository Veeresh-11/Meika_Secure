import json
import hashlib
from app.security.evidence.engine import GENESIS_HASH
from app.security.errors import SecurityInvariantViolation


# ---------------------------------------------------------
# EXPORT
# ---------------------------------------------------------

def export_evidence_store(store) -> list:
    """
    Export full evidence chain in deterministic order
    by walking the hash chain from last → genesis.
    """

    records = []

    current_hash = store.last_hash()

    if not current_hash:
        return []

    chain = []

    while current_hash and current_hash != GENESIS_HASH:
        record = store.get(current_hash)
        chain.append(record)
        current_hash = record.previous_hash

    chain.reverse()  # chronological order

    return chain


# ---------------------------------------------------------
# RESTORE
# ---------------------------------------------------------

def restore_evidence_store(store, records: list):
    """
    Restore evidence into empty store in strict order.
    """
    for record in records:
        store.append(record)


# ---------------------------------------------------------
# INTEGRITY VERIFICATION
# ---------------------------------------------------------

def verify_store_integrity(store) -> bool:
    """
    Full integrity replay of store.
    Validates:
    - Strict previous_hash linkage
    - Deterministic record hash recomputation
    - No sequence gaps
    """

    records = export_evidence_store(store)

    if not records:
        return True

    previous = GENESIS_HASH
    expected_sequence = 0

    for record in records:

        if record.sequence_number != expected_sequence:
            raise SecurityInvariantViolation("SEQUENCE_GAP")

        if record.previous_hash != previous:
            raise SecurityInvariantViolation("CHAIN_LINK_BROKEN")

        recomputed = hashlib.sha256(
            f"{record.sequence_number}|{record.previous_hash}|{record.payload_hash}".encode()
        ).hexdigest()

        if recomputed != record.record_hash:
            raise SecurityInvariantViolation("CHAIN_HASH_MISMATCH")

        previous = record.record_hash
        expected_sequence += 1

    return True


# ---------------------------------------------------------
# EXPORT FINGERPRINT
# ---------------------------------------------------------

def compute_export_hash(records: list) -> str:
    """
    Deterministic export fingerprint.
    """

    canonical = json.dumps(
        [
            {
                "sequence_number": r.sequence_number,
                "previous_hash": r.previous_hash,
                "payload_hash": r.payload_hash,
                "record_hash": r.record_hash,
            }
            for r in records
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(canonical).hexdigest()
