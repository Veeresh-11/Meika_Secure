# app/security/test_multi_anchor_integration.py

from app.security.track_d.anchoring.multi_anchor_client import MultiAnchorClient
from app.security.track_d.anchoring.anchor_providers.static_provider import StaticTestnetProvider


def test_multi_provider_threshold_success():
    providers = [
        StaticTestnetProvider(),
        StaticTestnetProvider(),
        StaticTestnetProvider(),
    ]

    multi = MultiAnchorClient(providers, minimum_success=2)

    receipts = multi.anchor("dummy_root_hash")

    assert len(receipts) >= 2
    assert multi.verify(receipts) is True
