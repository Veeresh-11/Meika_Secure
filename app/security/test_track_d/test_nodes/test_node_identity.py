import pytest
import hashlib
import json

from app.security.track_d.nodes.node_identity import NodeIdentity


VALID_CAPS = ["VERIFY", "CONSENSUS"]


def _valid_identity():
    return NodeIdentity(
        public_key=b"\x01" * 32,
        created_at="2026-01-01T00:00:00Z",
        capabilities=VALID_CAPS,
        weight=1,
    )


def test_node_id_deterministic():
    n1 = _valid_identity()
    n2 = _valid_identity()

    assert n1.node_id == n2.node_id


def test_node_id_changes_with_key():
    n1 = NodeIdentity(
        public_key=b"\x01" * 32,
        created_at="2026-01-01T00:00:00Z",
        capabilities=VALID_CAPS,
        weight=1,
    )

    n2 = NodeIdentity(
        public_key=b"\x02" * 32,
        created_at="2026-01-01T00:00:00Z",
        capabilities=VALID_CAPS,
        weight=1,
    )

    assert n1.node_id != n2.node_id


def test_invalid_timestamp_rejected():
    with pytest.raises(ValueError):
        NodeIdentity(
            public_key=b"\x01" * 32,
            created_at="invalid",
            capabilities=VALID_CAPS,
            weight=1,
        )


def test_expiry_before_creation_rejected():
    with pytest.raises(ValueError):
        NodeIdentity(
            public_key=b"\x01" * 32,
            created_at="2026-01-02T00:00:00Z",
            expires_at="2026-01-01T00:00:00Z",
            capabilities=VALID_CAPS,
            weight=1,
        )


def test_revocation_before_creation_rejected():
    with pytest.raises(ValueError):
        NodeIdentity(
            public_key=b"\x01" * 32,
            created_at="2026-01-02T00:00:00Z",
            revoked_at="2026-01-01T00:00:00Z",
            capabilities=VALID_CAPS,
            weight=1,
        )


def test_invalid_capability_rejected():
    with pytest.raises(ValueError):
        NodeIdentity(
            public_key=b"\x01" * 32,
            created_at="2026-01-01T00:00:00Z",
            capabilities=["UNKNOWN"],
            weight=1,
        )


def test_zero_weight_rejected():
    with pytest.raises(ValueError):
        NodeIdentity(
            public_key=b"\x01" * 32,
            created_at="2026-01-01T00:00:00Z",
            capabilities=VALID_CAPS,
            weight=0,
        )


def test_lifecycle_revoked():
    n = NodeIdentity(
        public_key=b"\x01" * 32,
        created_at="2026-01-01T00:00:00Z",
        revoked_at="2026-01-02T00:00:00Z",
        capabilities=VALID_CAPS,
        weight=1,
    )

    with pytest.raises(ValueError):
        n.validate_active("2026-01-03T00:00:00Z")


def test_lifecycle_expired():
    n = NodeIdentity(
        public_key=b"\x01" * 32,
        created_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-02T00:00:00Z",
        capabilities=VALID_CAPS,
        weight=1,
    )

    with pytest.raises(ValueError):
        n.validate_active("2026-01-03T00:00:00Z")
