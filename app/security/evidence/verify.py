# app/security/evidence/verify.py

from app.security.version import KERNEL_VERSION
import json
from typing import List
from app.security.evidence.models import EvidenceRecord
from app.security.errors import SecurityInvariantViolation
from app.security.evidence.engine import GENESIS_HASH
import hashlib

def verify_chain(records: List[EvidenceRecord]) -> bool:
    """
    Full chain replay verification.

    Validates:
    - Strict previous_hash linkage
    - Deterministic record_hash recomputation
    - No sequence gaps
    """
# Extract kernel_version from payload
# NOTE: payload_hash does not contain raw payload,
# so we cannot inspect it directly.
# Therefore version enforcement must occur at STORE LEVEL

    previous = GENESIS_HASH
    expected_sequence = 0

    for record in records:

        # 1️⃣ Enforce gap-free monotonic sequence
        if record.sequence_number != expected_sequence:
            raise SecurityInvariantViolation("SEQUENCE_GAP")

        # 2️⃣ Enforce strict previous hash linkage
        if record.previous_hash != previous:
            raise SecurityInvariantViolation("CHAIN_LINK_BROKEN")

        # 3️⃣ Recompute record_hash deterministically
        recomputed = hashlib.sha256(
            f"{record.sequence_number}|{record.previous_hash}|{record.payload_hash}".encode()
        ).hexdigest()

        if recomputed != record.record_hash:
            raise SecurityInvariantViolation("CHAIN_HASH_MISMATCH")

        previous = record.record_hash
        expected_sequence += 1

    return True
