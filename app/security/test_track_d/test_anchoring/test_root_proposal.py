import pytest
from app.security.track_d.anchoring.root_proposal import RootProposal


def test_deterministic_hash():
    p1 = RootProposal(
        merkle_root="abc",
        transparency_log_size=10,
        created_at="2026-01-01T00:00:00Z",
    )

    p2 = RootProposal(
        merkle_root="abc",
        transparency_log_size=10,
        created_at="2026-01-01T00:00:00Z",
    )

    assert p1.proposal_hash == p2.proposal_hash


def test_hash_changes_on_field_change():
    p1 = RootProposal(
        merkle_root="abc",
        transparency_log_size=10,
        created_at="2026-01-01T00:00:00Z",
    )

    p2 = RootProposal(
        merkle_root="xyz",
        transparency_log_size=10,
        created_at="2026-01-01T00:00:00Z",
    )

    assert p1.proposal_hash != p2.proposal_hash


def test_invalid_timestamp_rejected():
    with pytest.raises(ValueError):
        RootProposal(
            merkle_root="abc",
            transparency_log_size=10,
            created_at="invalid",
        )


def test_invalid_previous_hash_rejected():
    with pytest.raises(ValueError):
        RootProposal(
            merkle_root="abc",
            transparency_log_size=10,
            created_at="2026-01-01T00:00:00Z",
            previous_root_hash="short",
        )


def test_previous_hash_linkage():
    previous = "a" * 64

    p = RootProposal(
        merkle_root="abc",
        transparency_log_size=10,
        created_at="2026-01-01T00:00:00Z",
        previous_root_hash=previous,
    )

    assert p.previous_root_hash == previous
