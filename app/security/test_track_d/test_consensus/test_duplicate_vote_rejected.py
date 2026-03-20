import pytest
from app.security.track_d.consensus.proposal import ConsensusProposal
from app.security.track_d.consensus.quorum_engine import QuorumEngine
from app.security.track_d.nodes.node_identity import NodeIdentity
from app.security.track_d.nodes.node_registry import NodeRegistry


def test_duplicate_vote_rejected():

    registry = NodeRegistry()
    n1 = NodeIdentity.generate(weight=10)
    registry.register(n1)

    proposal = ConsensusProposal(
        proposal_type="MERKLE_ROOT",
        payload={"root": "abc"},
        created_at="2026-01-01T00:00:00Z",
        proposer_node_id=n1.node_id,
    )

    vote = n1.sign_vote(proposal.proposal_hash)

    engine = QuorumEngine(registry)

    with pytest.raises(ValueError):
        engine.evaluate(
            proposal=proposal,
            votes=[vote, vote],
            minimum_weight=10,
        )
