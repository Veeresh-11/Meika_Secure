"""
TRACK D — Consensus Proposal
Deterministic proposal object.
"""

from __future__ import annotations
import json
import hashlib
from typing import Dict, Any


def _canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class ConsensusProposal:

    def __init__(
        self,
        *,
        proposal_type: str,
        payload: Dict[str, Any],
        created_at: str,
        proposer_node_id: str,
    ):
        self._data = {
            "proposal_type": proposal_type,
            "payload": payload,
            "created_at": created_at,
            "proposer_node_id": proposer_node_id,
        }

        self._hash = hashlib.sha256(_canonical(self._data)).hexdigest()

    @property
    def proposal_hash(self) -> str:
        return self._hash

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._data, proposal_hash=self._hash)
