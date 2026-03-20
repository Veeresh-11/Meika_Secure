import pytest

from app.security.track_d.anchoring.multi_anchor_client import MultiAnchorClient
from app.security.track_d.anchoring.anchor_providers.static_provider import (
    StaticTestnetProvider,
)


def test_multi_anchor_success():

    p1 = StaticTestnetProvider()
    p2 = StaticTestnetProvider()

    client = MultiAnchorClient(
        providers=[p1, p2],
        minimum_success=2,
    )

    receipts = client.anchor("root-xyz")

    assert len(receipts) == 2
    assert client.verify(receipts) is True


def test_multi_anchor_insufficient():

    p1 = StaticTestnetProvider()
    p2 = StaticTestnetProvider()

    client = MultiAnchorClient(
        providers=[p1, p2],
        minimum_success=2,
    )

    # simulate failure by only using one provider
    receipts = [p1.submit_root("root-abc")]

    assert client.verify(receipts) is False


def test_invalid_minimum():

    p1 = StaticTestnetProvider()

    with pytest.raises(ValueError):
        MultiAnchorClient(
            providers=[p1],
            minimum_success=2,
        )
