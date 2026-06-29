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

def test_consensus_proposal_to_dict():
    from app.security.track_d.consensus.proposal import ConsensusProposal

    p = ConsensusProposal(
        proposal_type="upgrade",
        payload={"a": 1},
        created_at="2026",
        proposer_node_id="node1",
    )

    data = p.to_dict()

    assert data["proposal_type"] == "upgrade"
    assert "proposal_hash" in data

def test_consensus_result_to_dict():
    from app.security.track_d.consensus.consensus_result import ConsensusResult

    r = ConsensusResult(
        proposal_hash="abc",
        approved=True,
        total_weight=5,
        quorum=True,
        participating_nodes=["n1"],
    )

    data = r.to_dict()

    assert data["proposal_hash"] == "abc"
    assert data["approved"] is True