import pytest

from app.security.track_d.consensus.quorum_engine import QuorumEngine


def test_duplicate_vote_detected():

    class Vote:
        node_id = "node1"
        proposal_hash = "abc"

        def verify(self, *_):
            return True

    class Node:
        public_key_bytes = b"pub"
        weight = 1

    class Registry:
        def get_node(self, _):
            return Node()

    class Proposal:
        proposal_hash = "abc"

    engine = QuorumEngine(Registry())

    vote = Vote()

    with pytest.raises(ValueError, match="Duplicate vote detected"):
        engine.evaluate(
            proposal=Proposal(),
            votes=[vote, vote],
            minimum_weight=1,
        )


def test_vote_for_incorrect_proposal():

    class Vote:
        node_id = "node1"
        proposal_hash = "wrong"

        def verify(self, *_):
            return True

    class Node:
        public_key_bytes = b"pub"
        weight = 1

    class Registry:
        def get_node(self, _):
            return Node()

    class Proposal:
        proposal_hash = "correct"

    engine = QuorumEngine(Registry())

    with pytest.raises(ValueError, match="Vote for incorrect proposal"):
        engine.evaluate(
            proposal=Proposal(),
            votes=[Vote()],
            minimum_weight=1,
        )


def test_invalid_vote_signature():

    class Vote:
        node_id = "node1"
        proposal_hash = "abc"

        def verify(self, *_):
            return False

    class Node:
        public_key_bytes = b"pub"
        weight = 1

    class Registry:
        def get_node(self, _):
            return Node()

    class Proposal:
        proposal_hash = "abc"

    engine = QuorumEngine(Registry())

    with pytest.raises(ValueError, match="Invalid vote signature"):
        engine.evaluate(
            proposal=Proposal(),
            votes=[Vote()],
            minimum_weight=1,
        )


def test_quorum_success():

    class Vote:
        def __init__(self, node_id):
            self.node_id = node_id
            self.proposal_hash = "abc"

        def verify(self, *_):
            return True

    class Node:
        public_key_bytes = b"pub"

        def __init__(self, weight):
            self.weight = weight

    class Registry:
        def get_node(self, node_id):
            return Node(5)

    class Proposal:
        proposal_hash = "abc"

    engine = QuorumEngine(Registry())

    result = engine.evaluate(
        proposal=Proposal(),
        votes=[
            Vote("n1"),
            Vote("n2"),
        ],
        minimum_weight=10,
    )

    assert result.quorum is True
    assert result.total_weight == 10