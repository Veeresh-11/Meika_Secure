from __future__ import annotations

from ..consensus.quorum_engine import QuorumEngine
from .models import VerificationResponse


class ConsensusVerifier:

    def __init__(self, quorum_engine: QuorumEngine):
        self.quorum_engine = quorum_engine

    def verify(
        self,
        proposal,
        votes,
        minimum_weight: int,
    ) -> VerificationResponse:

        result = self.quorum_engine.evaluate(
            proposal=proposal,
            votes=votes,
            minimum_weight=minimum_weight,
        )

        # Use correct field from ConsensusResult
        quorum_met = getattr(result, "quorum_met", None)
        if quorum_met is None:
            quorum_met = getattr(result, "quorum", None)
        if quorum_met is None:
            quorum_met = getattr(result, "success", False)

        if not quorum_met:
            return VerificationResponse(
                verified=False,
                object_type="CONSENSUS",
                object_id=proposal.proposal_hash,
                proof=None,
            )

        return VerificationResponse(
            verified=True,
            object_type="CONSENSUS",
            object_id=proposal.proposal_hash,
            proof={
               "total_weight": result.total_weight,
               "participants": getattr(
                   result,
                   "participating_nodes",
                   getattr(result, "participants", []),
                ),
            },
        )
