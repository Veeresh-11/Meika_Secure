"""
TRACK D — Canonical Error Code Registry
======================================

This module defines the stable, global error semantics for Track D.

SECURITY LAW:
- Error codes are PART OF THE INTERFACE CONTRACT
- Codes MUST NEVER change meaning
- Codes MUST NEVER be reused
- Codes MUST survive refactors, rewrites, and migrations

This file contains:
- ErrorClass (what failed)
- ErrorStage (where it failed)
- ErrorCode registry (why it failed)

NO runtime logic is allowed here.
"""

from enum import Enum
from typing import NamedTuple, Dict


# ---------------------------------------------------------------------
# Error Classes (WHAT failed)
# ---------------------------------------------------------------------

class ErrorClass(str, Enum):
    CONTEXT = "CONTEXT"
    AUTH = "AUTH"
    DEVICE = "DEVICE"
    GRANT = "GRANT"
    POLICY = "POLICY"
    EVIDENCE = "EVIDENCE"
    REPLAY = "REPLAY"
    STORAGE = "STORAGE"
    EXPORT = "EXPORT"
    SIMULATION = "SIMULATION"
    INFRA = "INFRA"


# ---------------------------------------------------------------------
# Error Stages (WHERE it failed)
# ---------------------------------------------------------------------

class ErrorStage(str, Enum):
    INPUT = "INPUT"
    ORDER = "ORDER"
    CHAIN = "CHAIN"
    HASH = "HASH"
    REPLAY = "REPLAY"
    EXPORT = "EXPORT"
    SIMULATION = "SIMULATION"
    INTERNAL = "INTERNAL"


# ---------------------------------------------------------------------
# Error Code Definition
# ---------------------------------------------------------------------

class ErrorDefinition(NamedTuple):
    code: str
    error_class: ErrorClass
    stage: ErrorStage
    description: str


# ---------------------------------------------------------------------
# Canonical Error Code Registry
# ---------------------------------------------------------------------

ERROR_CODES: Dict[str, ErrorDefinition] = {

    # ----------------------------
    # Replay / Evidence Errors
    # ----------------------------

    "MEIKA_REPLAY_INPUT_INVALID": ErrorDefinition(
        code="MEIKA_REPLAY_INPUT_INVALID",
        error_class=ErrorClass.REPLAY,
        stage=ErrorStage.INPUT,
        description="Evidence input is malformed or non-iterable",
    ),

    "MEIKA_REPLAY_EMPTY_CHAIN": ErrorDefinition(
        code="MEIKA_REPLAY_EMPTY_CHAIN",
        error_class=ErrorClass.REPLAY,
        stage=ErrorStage.CHAIN,
        description="Evidence chain is empty",
    ),

    "MEIKA_REPLAY_SEQUENCE_GAP": ErrorDefinition(
        code="MEIKA_REPLAY_SEQUENCE_GAP",
        error_class=ErrorClass.REPLAY,
        stage=ErrorStage.ORDER,
        description="Evidence sequence numbers are not contiguous",
    ),

    "MEIKA_REPLAY_PREVIOUS_HASH_MISMATCH": ErrorDefinition(
        code="MEIKA_REPLAY_PREVIOUS_HASH_MISMATCH",
        error_class=ErrorClass.EVIDENCE,
        stage=ErrorStage.CHAIN,
        description="previous_hash does not match prior record hash",
    ),

    "MEIKA_REPLAY_HASH_COMPUTE_FAILED": ErrorDefinition(
        code="MEIKA_REPLAY_HASH_COMPUTE_FAILED",
        error_class=ErrorClass.EVIDENCE,
        stage=ErrorStage.HASH,
        description="Evidence hash could not be recomputed",
    ),

    "MEIKA_REPLAY_HASH_MISMATCH": ErrorDefinition(
        code="MEIKA_REPLAY_HASH_MISMATCH",
        error_class=ErrorClass.EVIDENCE,
        stage=ErrorStage.HASH,
        description="Computed hash does not match stored record hash",
    ),

    # ----------------------------
    # Export Errors
    # ----------------------------

    "MEIKA_EXPORT_BUNDLE_INVALID": ErrorDefinition(
        code="MEIKA_EXPORT_BUNDLE_INVALID",
        error_class=ErrorClass.EXPORT,
        stage=ErrorStage.EXPORT,
        description="Generated export bundle failed verification",
    ),

    # ----------------------------
    # Simulation Errors
    # ----------------------------

    "MEIKA_SIMULATION_FORBIDDEN_EFFECT": ErrorDefinition(
        code="MEIKA_SIMULATION_FORBIDDEN_EFFECT",
        error_class=ErrorClass.SIMULATION,
        stage=ErrorStage.SIMULATION,
        description="Simulation attempted an authoritative side effect",
    ),
}


# ---------------------------------------------------------------------
# Safety Helpers
# ---------------------------------------------------------------------

def get_error_definition(code: str) -> ErrorDefinition:
    """
    Resolve an error code to its canonical definition.

    Raises KeyError if code is unknown.
    """
    return ERROR_CODES[code]
