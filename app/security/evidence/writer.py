# app/security/evidence/writer.py
"""
TRACK B — Evidence Writer (Compatibility Layer)

This module provides a compatibility wrapper for:
- Legacy paths
- Isolated tests
- Transitional integrations

Responsibilities:
- Delegate evidence construction to the canonical engine
- Enforce fail-closed semantics on commit
- Provide a minimal write interface

IMPORTANT:
This module is NOT authoritative.
All security invariants live in:
- evidence.engine
- evidence.store

Future tracks may deprecate this file entirely.
"""

from typing import Optional

from app.security.evidence.engine import build_evidence_record
from app.security.evidence.store import InMemoryEvidenceStore
from app.security.errors import SecurityInvariantViolation


class EvidenceWriter:
    """
    Track-B Evidence Writer

    This is a compatibility wrapper used ONLY by tests and legacy paths.
    All evidence MUST be constructed via the canonical engine.
    """

    def __init__(self, store: Optional[InMemoryEvidenceStore] = None):
        self.store = store or InMemoryEvidenceStore()

    def write_decision(self, context, decision) -> str:
        """
        Append a decision as an evidence record.

        FAIL-CLOSED on any invariant violation.
        """

        record = build_evidence_record(
            context=context,
            policy=None,
            risk=None,
            authority=[],
            decision=decision,
            extra_metadata={},
            store=self.store,
        )

        committed = self.store.append(record)
        if not committed:
            raise SecurityInvariantViolation("EVIDENCE_COMMIT_FAILED")

        return committed
