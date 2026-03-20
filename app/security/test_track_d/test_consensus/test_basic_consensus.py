import pytest
from app.security.track_d.consensus.proposal import ConsensusProposal
from app.security.track_d.consensus.vote import Vote
from app.security.track_d.consensus.quorum_engine import QuorumEngine
from app.security.track_d.nodes.node_identity import NodeIdentity
from app.security.track_d.nodes.node_registry import NodeRegistry


def test_basic_quorum_success():

    registry = NodeRegistry()

    n1 = NodeIdentity.generate(weight=5)
    n2 = NodeIdentity.generate(weight=5)

    registry.register(n1)
    registry.register(n2)

    proposal = ConsensusProposal(
        proposal_type="MERKLE_ROOT",
        payload={"root": "abc"},
        created_at="2026-01-01T00:00:00Z",
        proposer_node_id=n1.node_id,
    )

    vote1 = n1.sign_vote(proposal.proposal_hash)
    vote2 = n2.sign_vote(proposal.proposal_hash)

    engine = QuorumEngine(registry)

    result = engine.evaluate(
        proposal=proposal,
        votes=[vote1, vote2],
        minimum_weight=10,
    )

    assert result.approved

