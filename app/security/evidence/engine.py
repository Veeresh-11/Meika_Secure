
# app/security/evidence/engine.py

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from app.security.version import KERNEL_VERSION
from app.security.evidence.models import EvidenceRecord
from app.security.errors import SecurityInvariantViolation
from app.security.version import KERNEL_BUILD_HASH

GENESIS_HASH = "0" * 64


# ---------------------------------------------------------
# RECEIPT
# ---------------------------------------------------------

@dataclass(frozen=True)
class EvidenceCommitReceipt:
    merkle_root: str
    committed_at: datetime


# ---------------------------------------------------------
# INTERNAL HELPERS
# ---------------------------------------------------------

def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------
# DECISION RECORD
# ---------------------------------------------------------

def build_evidence_record(
    *,
    context,
    policy,
    risk,
    authority,
    decision,
    extra_metadata: dict,
    store,
) -> EvidenceRecord:

    sequence_number: int = store.next_sequence()
    previous_hash: str = store.last_hash() or GENESIS_HASH

    payload = {
        "type": "DECISION",
        "context": context.to_dict(),
        "kernel_version": KERNEL_VERSION,
        "kernel_build_hash": KERNEL_BUILD_HASH,
        "decision": {
            "outcome": decision.outcome.value,
            "reason": decision.reason,
            "policy_version": decision.policy_version,
        },
        "policy": policy,
        "risk": risk,
        "authority": authority,
        "meta": extra_metadata,
    }

    payload_hash = _sha256(
        _canonical_json(payload).encode("utf-8")
    )

    record_hash = _sha256(
        f"{sequence_number}|{previous_hash}|{payload_hash}".encode("utf-8")
    )

    return EvidenceRecord(
        sequence_number=sequence_number,
        previous_hash=previous_hash,
        payload_hash=payload_hash,
        record_hash=record_hash,
    )


# ---------------------------------------------------------
# ANCHOR RECORD
# ---------------------------------------------------------

def build_anchor_record(
    *,
    root_hash: str,
    record_count: int,
    anchor_receipt,
    store,
) -> EvidenceRecord:

    sequence_number: int = store.next_sequence()
    previous_hash: str = store.last_hash() or GENESIS_HASH

    payload = {
        "type": "ANCHOR_RECEIPT",
        "kernel_version": KERNEL_VERSION,
        "kernel_build_hash": KERNEL_BUILD_HASH,
        "root_hash": root_hash,
        "record_count": record_count,
        "anchor_receipt": anchor_receipt,
    }

    payload_hash = _sha256(
        _canonical_json(payload).encode("utf-8")
    )

    record_hash = _sha256(
        f"{sequence_number}|{previous_hash}|{payload_hash}".encode("utf-8")
    )

    return EvidenceRecord(
        sequence_number=sequence_number,
        previous_hash=previous_hash,
        payload_hash=payload_hash,
        record_hash=record_hash,
    )


# ---------------------------------------------------------
# APPEND
# ---------------------------------------------------------

def append_evidence_record(
    record: EvidenceRecord,
    *,
    store,
) -> Optional[EvidenceCommitReceipt]:

    try:
        root = store.append(record)
        return EvidenceCommitReceipt(
            merkle_root=root,
            committed_at=datetime.utcnow(),
        )
    except Exception:
        return None

def build_governance_upgrade_record(
    *,
    manifest,
    store,
):
    sequence_number = store.next_sequence()
    previous_hash = store.last_hash() or GENESIS_HASH

    payload = {
        "type": "SCHEMA_UPGRADE",
        "migration_id": manifest.migration_id,
        "from_version": manifest.from_version,
        "to_version": manifest.to_version,
        "migration_hash": manifest.migration_hash,
        "signed_by": manifest.signed_by,
    }

    payload_hash = _sha256(
        _canonical_json(payload).encode("utf-8")
    )

    record_hash = _sha256(
        f"{sequence_number}|{previous_hash}|{payload_hash}".encode("utf-8")
    )

    return EvidenceRecord(
        sequence_number=sequence_number,
        previous_hash=previous_hash,
        payload_hash=payload_hash,
        record_hash=record_hash,
    )
