from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.security.track_d.consensus.vote import Vote


def test_vote_verify_success():
    private_key = Ed25519PrivateKey.generate()

    public_key = private_key.public_key()

    payload = (
        b'{"node_id":"node1","proposal_hash":"abc","signed_at":"2026"}'
    )

    signature = private_key.sign(payload)

    vote = Vote(
        node_id="node1",
        proposal_hash="abc",
        signed_at="2026",
        signature=signature.hex(),
    )

    assert vote.verify(
        public_key.public_bytes_raw()
    )


def test_vote_verify_failure():
    private_key = Ed25519PrivateKey.generate()
    wrong_key = Ed25519PrivateKey.generate()

    payload = (
        b'{"node_id":"node1","proposal_hash":"abc","signed_at":"2026"}'
    )

    signature = private_key.sign(payload)

    vote = Vote(
        node_id="node1",
        proposal_hash="abc",
        signed_at="2026",
        signature=signature.hex(),
    )

    assert (
        vote.verify(
            wrong_key.public_key().public_bytes_raw()
        )
        is False
    )