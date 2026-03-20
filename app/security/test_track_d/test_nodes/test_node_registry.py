import pytest

from app.security.track_d.nodes.node_identity import NodeIdentity
from app.security.track_d.nodes.node_registry import NodeRegistry


VALID_CAPS = ["VERIFY"]


def _node(pk_byte):
    return NodeIdentity(
        public_key=bytes([pk_byte]) * 32,
        created_at="2026-01-01T00:00:00Z",
        capabilities=VALID_CAPS,
        weight=1,
    )


def test_register_node_success():
    reg = NodeRegistry()
    node = _node(1)

    reg.register(node)

    assert reg.get(node.node_id) is not None


def test_duplicate_node_rejected():
    reg = NodeRegistry()
    node = _node(1)

    reg.register(node)

    with pytest.raises(ValueError):
        reg.register(node)


def test_revoked_node_not_active():
    reg = NodeRegistry()

    node = NodeIdentity(
        public_key=b"\x01" * 32,
        created_at="2026-01-01T00:00:00Z",
        revoked_at="2026-01-02T00:00:00Z",
        capabilities=VALID_CAPS,
        weight=1,
    )

    reg.register(node)

    with pytest.raises(ValueError):
        reg.get_active(node.node_id, "2026-01-03T00:00:00Z")


def test_expired_node_not_active():
    reg = NodeRegistry()

    node = NodeIdentity(
        public_key=b"\x01" * 32,
        created_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-02T00:00:00Z",
        capabilities=VALID_CAPS,
        weight=1,
    )

    reg.register(node)

    with pytest.raises(ValueError):
        reg.get_active(node.node_id, "2026-01-03T00:00:00Z")
