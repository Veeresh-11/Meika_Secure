"""
TRACK D — Replay Verification API
================================

Authoritative, read-only replay verification for evidence chains.

This module provides a pure, deterministic verifier that validates
evidence produced by Track B and stored under Track C.

SECURITY LAW:
- Replay is the highest authority.
- No mutation.
- No recovery.
- No heuristics.
- Fail closed.

This module MUST NOT:
- Touch kernel logic (Track A)
- Write or modify evidence (Track B)
- Depend on storage tier or runtime state (Track C)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, List

from app.security.evidence.models import EvidenceRecord
from app.security.evidence.engine import EvidenceHashEngine
from app.security.errors import SecurityInvariantViolation


# ---------------------------------------------------------------------
# Replay Result Model
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class ReplayResult:
    """
    Result of replay verification.

    valid:
        True if the chain is cryptographically and structurally valid.

    failure_code:
        Stable machine-readable reason for failure.

    failure_stage:
        Stage at which verification failed (e.g. CHAIN, HASH, ORDER).

    failure_message:
        Safe, human-readable explanation.
    """

    valid: bool
    failure_code: Optional[str] = None
    failure_stage: Optional[str] = None
    failure_message: Optional[str] = None


# ---------------------------------------------------------------------
# Replay Verification Core
# ---------------------------------------------------------------------

def verify_evidence_chain(
    records: Iterable[EvidenceRecord],
) -> ReplayResult:
    """
    Verify an ordered evidence chain.

    INPUT:
        records:
            Ordered iterable of EvidenceRecord objects.

    OUTPUT:
        ReplayResult indicating VALID or INVALID.

    VERIFICATION RULES:
        - Records must be strictly ordered by sequence number.
        - Each record's previous_hash must match the prior record hash.
        - Each record hash must recompute deterministically.
        - No gaps, no reordering, no mutation.

    FAILURE MODE:
        - Fail closed.
        - No partial acceptance.
        - No recovery or guessing.
    """

    try:
        chain: List[EvidenceRecord] = list(records)
    except Exception:
        return ReplayResult(
            valid=False,
            failure_code="MEIKA_REPLAY_INPUT_INVALID",
            failure_stage="INPUT",
            failure_message="Evidence input is not iterable",
        )

    if not chain:
        return ReplayResult(
            valid=False,
            failure_code="MEIKA_REPLAY_EMPTY_CHAIN",
            failure_stage="CHAIN",
            failure_message="Evidence chain is empty",
        )

    # Enforce strict ordering and hash linkage
    previous: Optional[EvidenceRecord] = None

    for index, record in enumerate(chain):
        # -------------------------------------------------------------
        # Sequence ordering
        # -------------------------------------------------------------
        if previous is not None:
            if record.sequence != previous.sequence + 1:
                return ReplayResult(
                    valid=False,
                    failure_code="MEIKA_REPLAY_SEQUENCE_GAP",
                    failure_stage="ORDER",
                    failure_message=(
                        f"Sequence break at index {index}: "
                        f"expected {previous.sequence + 1}, got {record.sequence}"
                    ),
                )

            if record.previous_hash != previous.record_hash:
                return ReplayResult(
                    valid=False,
                    failure_code="MEIKA_REPLAY_PREVIOUS_HASH_MISMATCH",
                    failure_stage="CHAIN",
                    failure_message=(
                        f"Previous hash mismatch at sequence {record.sequence}"
                    ),
                )

        # -------------------------------------------------------------
        # Hash recomputation
        # -------------------------------------------------------------
        try:
            computed_hash = EvidenceHashEngine.compute_record_hash(record)
        except Exception:
            return ReplayResult(
                valid=False,
                failure_code="MEIKA_REPLAY_HASH_COMPUTE_FAILED",
                failure_stage="HASH",
                failure_message=(
                    f"Hash computation failed at sequence {record.sequence}"
                ),
            )

        if computed_hash != record.record_hash:
            return ReplayResult(
                valid=False,
                failure_code="MEIKA_REPLAY_HASH_MISMATCH",
                failure_stage="HASH",
                failure_message=(
                    f"Hash mismatch at sequence {record.sequence}"
                ),
            )

        previous = record

    # -----------------------------------------------------------------
    # If we reached here, the entire chain is valid
    # -----------------------------------------------------------------

    return ReplayResult(valid=True)


# ---------------------------------------------------------------------
# Safety Wrapper (Optional)
# ---------------------------------------------------------------------

def verify_or_raise(records: Iterable[EvidenceRecord]) -> None:
    """
    Strict verification helper.

    Raises SecurityInvariantViolation on failure.
    Useful for:
        - SOC2 export validation
        - Internal guardrails
        - Test assertions
    """

    result = verify_evidence_chain(records)

    if not result.valid:
        raise SecurityInvariantViolation(
            f"[{result.failure_code}] {result.failure_message}"
        )
