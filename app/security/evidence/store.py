# app/security/evidence/store.py
"""
TRACK B — Append-Only Evidence Store

This module enforces physical evidence invariants.

Guarantees:
- Append-only semantics
- No overwrite
- No delete
- Strict hash chaining
- Monotonic, gap-free sequencing
- Fail-closed on any violation

This implementation is:
- In-memory
- Single-process
- Deterministic

Security note:
This store enforces invariants — it does NOT create evidence.
Evidence validity depends on the engine, not the store.

Track-C will replace or extend this store
with persistent and tiered memory models.
"""

from threading import Lock
from typing import Dict, List, Optional

from app.security.evidence.models import EvidenceRecord
from app.security.errors import SecurityInvariantViolation
from app.security.evidence.engine import GENESIS_HASH
from app.security.evidence.factory import get_evidence_store

EvidenceStore = get_evidence_store

class InMemoryEvidenceStore:
    """
    Append-only evidence store (Track-B).

    INVARIANTS:
    - Append-only
    - No overwrite
    - No delete
    - Strict hash chaining
    - Monotonic sequence numbers
    """

    def __init__(self):
        self._records: Dict[str, EvidenceRecord] = {}
        self._order: List[str] = []
        self._last_hash: Optional[str] = None
        self._sequence: int = 0
        self._lock = Lock()

    def next_sequence(self) -> int:
        return self._sequence

    def last_hash(self) -> Optional[str]:
        return self._last_hash

    def append(self, record: EvidenceRecord) -> str:
        with self._lock:
            expected_prev = self._last_hash or GENESIS_HASH

            if record.previous_hash != expected_prev:
                raise SecurityInvariantViolation("EVIDENCE_CHAIN_BROKEN")

            if record.record_hash in self._records:
                raise SecurityInvariantViolation("EVIDENCE_DUPLICATE_HASH")

            self._records[record.record_hash] = record
            self._order.append(record.record_hash)

            self._last_hash = record.record_hash
            self._sequence += 1

            return record.record_hash

    def hashes(self) -> List[str]:
        return list(self._order)

    def get(self, record_hash: str) -> EvidenceRecord:
        return self._records[record_hash]

    def all(self) -> Dict[str, EvidenceRecord]:
        return dict(self._records)


# Canonical alias
EvidenceStore = InMemoryEvidenceStore
