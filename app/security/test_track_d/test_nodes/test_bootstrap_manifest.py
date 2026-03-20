import pytest

from app.security.track_d.nodes.bootstrap_manifest import BootstrapManifest
from app.security.track_d.nodes.node_identity import NodeIdentity
from app.security.track_d.signing.ed25519_local import Ed25519LocalSigner


def _node(pk):
    return NodeIdentity(
        public_key=bytes([pk]) * 32,
        created_at="2026-01-01T00:00:00Z",
        capabilities=["VERIFY"],
        weight=1,
    )


def test_bootstrap_signature_valid():
    signer = Ed25519LocalSigner()

    node = _node(1)

    bootstrap = BootstrapManifest(
        genesis_nodes=[node],
        created_at="2026-01-01T00:00:00Z",
    )

    sig = bootstrap.sign(signer)

    assert bootstrap.verify(sig, signer.public_key_hex())


def test_bootstrap_tampering_detected():
    signer = Ed25519LocalSigner()
    node = _node(1)

    bootstrap = BootstrapManifest(
        genesis_nodes=[node],
        created_at="2026-01-01T00:00:00Z",
    )

    sig = bootstrap.sign(signer)

    bootstrap.genesis_nodes.append(_node(2))

    with pytest.raises(ValueError):
        bootstrap.verify(sig, signer.public_key_hex())


def test_duplicate_genesis_node_rejected():
    node = _node(1)

    with pytest.raises(ValueError):
        BootstrapManifest(
            genesis_nodes=[node, node],
            created_at="2026-01-01T00:00:00Z",
        )
