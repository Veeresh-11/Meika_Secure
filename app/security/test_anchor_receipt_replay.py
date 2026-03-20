# app/security/test_anchor_receipt_replay.py

from app.security.track_d.anchoring.multi_anchor_client import MultiAnchorClient
from app.security.track_d.anchoring.anchor_providers.static_provider import StaticTestnetProvider


def test_anchor_receipt_replay_verification():
    providers = [
        StaticTestnetProvider(),
        StaticTestnetProvider(),
    ]

    multi = MultiAnchorClient(providers, minimum_success=2)

    receipts = multi.anchor("root_hash")

    # First verification
    assert multi.verify(receipts) is True

    # Replay verification (should still succeed)
    assert multi.verify(receipts) is True
