"""
TRACK D — SOC2 / ISO Compliance Export Generator (Hardened + Compatible)
"""

from __future__ import annotations

import json
import hashlib
from typing import List, Dict, Any, Optional

from .signing.signer_interface import ISigner
from .signing.ed25519_local import Ed25519LocalSigner


def _canonical_json(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def generate_soc2_export(
    *,
    evidence_records: List[Dict[str, Any]],
    kernel_version: str,
    export_period: Dict[str, str],
    control_mapping: Dict[str, Any],
    signer: Optional[ISigner] = None,  # ✅ FIX: optional again
) -> Dict[str, Any]:

    if signer is None:
        signer = Ed25519LocalSigner()

    if not evidence_records:
        raise ValueError("evidence_records must not be empty")

    base_payload = {
        "export_type": "SOC2_TYPE_II",
        "period_start": export_period["start"],
        "period_end": export_period["end"],
        "generated_at": export_period["end"],
        "kernel_version": kernel_version,
        "hash_algorithm": "SHA-256",
        "records": list(evidence_records),
        "controls": control_mapping,
    }

    canonical = _canonical_json(base_payload)
    bundle_hash = hashlib.sha256(canonical).hexdigest()

    # ✅ FIX: unpack tuple
    signature_hex, key_id = signer.sign(canonical)

    export_payload = dict(base_payload)
    export_payload["bundle_hash"] = bundle_hash
    export_payload["signature"] = signature_hex
    export_payload["signing_algorithm"] = signer.algorithm()
    export_payload["key_id"] = key_id

    return export_payload
