import pytest

from app.security.track_d.nodes.node_manifest import NodeManifest
from app.security.track_d.signing.ed25519_local import Ed25519LocalSigner


def test_manifest_sign_verify():
    signer = Ed25519LocalSigner()

    manifest = NodeManifest(
        node_id="abc",
        public_key_hex=signer.public_key_hex(),
        capabilities=["VERIFY"],
        weight=1,
        created_at="2026-01-01T00:00:00Z",
    )

    sig = manifest.sign(signer)

    assert manifest.verify(sig)


def test_manifest_tampering_detected():
    signer = Ed25519LocalSigner()

    manifest = NodeManifest(
        node_id="abc",
        public_key_hex=signer.public_key_hex(),
        capabilities=["VERIFY"],
        weight=1,
        created_at="2026-01-01T00:00:00Z",
    )

    sig = manifest.sign(signer)

    manifest.weight = 999

    with pytest.raises(ValueError):
        manifest.verify(sig)
