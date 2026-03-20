import pytest
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.security.track_d.certificates.root_certificate import RootCertificate


def _keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    return private, public.public_bytes_raw()


def test_certificate_valid_signature():

    private, public_bytes = _keypair()

    cert = RootCertificate.issue(
        cluster_id="CLUSTER-1",
        proposal_hash="abc",
        merkle_root="root123",
        participants=["n1", "n2"],
        total_weight=10,
        minimum_weight=10,
        created_at="2026-01-01T00:00:00Z",
        private_key=private,
    )

    assert cert.verify(public_bytes)


def test_tampering_detected():

    private, public_bytes = _keypair()

    cert = RootCertificate.issue(
        cluster_id="CLUSTER-1",
        proposal_hash="abc",
        merkle_root="root123",
        participants=["n1", "n2"],
        total_weight=10,
        minimum_weight=10,
        created_at="2026-01-01T00:00:00Z",
        private_key=private,
    )

    tampered = RootCertificate(
        cluster_id=cert.cluster_id,
        proposal_hash="changed",
        merkle_root=cert.merkle_root,
        participants=cert.participants,
        total_weight=cert.total_weight,
        minimum_weight=cert.minimum_weight,
        created_at=cert.created_at,
        signature=cert.signature,
    )

    with pytest.raises(ValueError):
        tampered.verify(public_bytes)


def test_deterministic_hash():

    private, _ = _keypair()

    cert1 = RootCertificate.issue(
        cluster_id="CLUSTER-1",
        proposal_hash="abc",
        merkle_root="root123",
        participants=["n2", "n1"],  # unordered
        total_weight=10,
        minimum_weight=10,
        created_at="2026-01-01T00:00:00Z",
        private_key=private,
    )

    cert2 = RootCertificate.issue(
        cluster_id="CLUSTER-1",
        proposal_hash="abc",
        merkle_root="root123",
        participants=["n1", "n2"],  # reversed
        total_weight=10,
        minimum_weight=10,
        created_at="2026-01-01T00:00:00Z",
        private_key=private,
    )

    assert cert1.certificate_hash() == cert2.certificate_hash()
