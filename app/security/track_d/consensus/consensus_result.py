"""
TRACK D — Consensus Result
Final deterministic output.
"""

from __future__ import annotations
from typing import List


class ConsensusResult:

    def __init__(
        self,
        *,
        proposal_hash: str,
        approved: bool,
        total_weight: int,
        quorum: bool,
        participating_nodes: List[str],
    ):
        self.proposal_hash = proposal_hash
        self.approved = approved
        self.total_weight = total_weight
        self.participating_nodes = list(participating_nodes)
        self.quorum = quorum

    def to_dict(self):
        return {
            "proposal_hash": self.proposal_hash,
            "approved": self.approved,
            "total_weight": self.total_weight,
            "participating_nodes": list(self.participating_nodes),
        }
