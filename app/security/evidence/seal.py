# app/security/evidence/seal.py

from typing import Optional
from datetime import datetime
import json
import hashlib

from app.security.evidence.verify import verify_chain
from app.security.evidence.engine import GENESIS_HASH
from app.security.evidence.models import EvidenceRecord


def compute_root_hash(records: list[EvidenceRecord]) -> str:
    """
    Computes the canonical ledger root hash.

    Verifies full chain before returning root.
    """
    if not records:
        return GENESIS_HASH

    # Ensure chain integrity before sealing
    verify_chain(records)

    return records[-1].record_hash


def create_seal_snapshot(records: list[EvidenceRecord]) -> dict:
    """
    Creates a signed snapshot payload (unsigned for now).

    Future: integrate with Track D signing.
    """
    root_hash = compute_root_hash(records)

    snapshot = {
        "root_hash": root_hash,
        "record_count": len(records),
        "sealed_at": datetime.utcnow().isoformat(),
    }

    # Deterministic seal hash
    snapshot_hash = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return {
        "snapshot": snapshot,
        "snapshot_hash": snapshot_hash,
    }
