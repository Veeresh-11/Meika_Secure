import pytest

from app.security.track_d.anchoring.multi_anchor_client import MultiAnchorClient
from app.security.track_d.anchoring.anchor_providers.static_provider import (
    StaticTestnetProvider,
)

from app.security.track_d.anchoring.anchor_receipt import AnchorReceipt


class MockProvider:
    def __init__(self, network="mock", verify_result=True):
        self._network = network
        self._verify_result = verify_result

    def network_id(self):
        return self._network

    def submit_root(self, root_hash):
        return AnchorReceipt.create(
            root_hash=root_hash,
            network=self._network,
            transaction_id="tx1",
            block_number=1,
            anchored_at="2026-01-01T00:00:00Z",
        )

    def verify_on_chain(self, receipt):
        return self._verify_result
    

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

def test_empty_provider_list_rejected():
    with pytest.raises(
        ValueError,
        match="At least one provider required",
    ):
        MultiAnchorClient([], 1)
        
def test_zero_minimum_success_rejected():
    provider = MockProvider()

    with pytest.raises(
        ValueError,
        match="minimum_success must be > 0",
    ):
        MultiAnchorClient([provider], 0)
        
class BadReceiptProvider:

    def network_id(self):
        return "mock"

    def submit_root(self, root):
        return "not a receipt"

    def verify_on_chain(self, receipt):
        return True


def test_invalid_receipt_type_causes_failure():

    client = MultiAnchorClient(
        [BadReceiptProvider()],
        minimum_success=1,
    )

    with pytest.raises(
        ValueError,
        match="Insufficient anchor confirmations",
    ):
        client.anchor("abc")
        
def test_verify_empty_receipts():
    provider = MockProvider()

    client = MultiAnchorClient(
        [provider],
        minimum_success=1,
    )

    assert client.verify([]) is False
    
def test_verify_unknown_provider():

    provider = MockProvider()

    client = MultiAnchorClient(
        [provider],
        minimum_success=1,
    )

    receipt = AnchorReceipt.create(
        root_hash="a"*64,
        network="UNKNOWN",
        transaction_id="tx",
        block_number=1,
        anchored_at="2026-01-01T00:00:00Z",
    )

    assert client.verify([receipt]) is False
    
class ExplodingProvider(MockProvider):

    def verify_on_chain(self, receipt):
        raise RuntimeError("boom")
    
def test_provider_verify_exception():

    provider = ExplodingProvider()

    client = MultiAnchorClient(
        [provider],
        minimum_success=1,
    )

    receipt = AnchorReceipt.create(
        root_hash="a"*64,
        network=provider.network_id(),
        transaction_id="tx",
        block_number=1,
        anchored_at="2026-01-01T00:00:00Z",
    )

    assert client.verify([receipt]) is False
    
class FalseProvider(MockProvider):

    def verify_on_chain(self, receipt):
        return False
    
def test_verify_returns_false():

    provider = FalseProvider()

    client = MultiAnchorClient(
        [provider],
        minimum_success=1,
    )

    receipt = AnchorReceipt.create(
        root_hash="a"*64,
        network=provider.network_id(),
        transaction_id="tx",
        block_number=1,
        anchored_at="2026-01-01T00:00:00Z",
    )

    assert client.verify([receipt]) is False
    
