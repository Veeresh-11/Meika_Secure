"""
TRACK D — Quorum Engine
Weighted Byzantine-safe vote aggregation.
"""

from __future__ import annotations
from typing import List, Dict, Set

from .proposal import ConsensusProposal
from .vote import Vote
from .consensus_result import ConsensusResult
from ..nodes.node_registry import NodeRegistry


class QuorumEngine:

    def __init__(self, node_registry: NodeRegistry):
        self.node_registry = node_registry

    def evaluate(
        self,
        *,
        proposal: ConsensusProposal,
        votes: List[Vote],
        minimum_weight: int,
    ) -> ConsensusResult:

        seen_nodes: Set[str] = set()
        total_weight = 0
        participants: List[str] = []

        for vote in votes:

            if vote.node_id in seen_nodes:
                raise ValueError("Duplicate vote detected")

            if vote.proposal_hash != proposal.proposal_hash:
                raise ValueError("Vote for incorrect proposal")

            node = self.node_registry.get_node(vote.node_id)

            if not vote.verify(node.public_key_bytes):
                raise ValueError("Invalid vote signature")

            seen_nodes.add(vote.node_id)

            total_weight += node.weight
            participants.append(vote.node_id)

        approved = total_weight >= minimum_weight

        return ConsensusResult(
            proposal_hash=proposal.proposal_hash,
            quorum=approved,
            approved=approved,
            total_weight=total_weight,
            participating_nodes=participants,
        )

