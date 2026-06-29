from app.security.track_d.anchoring.anchor_providers.static_provider import (
    StaticTestnetProvider,
)
from app.security.track_d.anchoring.anchor_receipt import AnchorReceipt

def test_static_anchor_and_verify():

    provider = StaticTestnetProvider()

    receipt = provider.submit_root("root-abc")

    assert provider.verify_on_chain(receipt) is True
    assert receipt.network == "STATIC_TESTNET"
    
def test_verify_on_chain_missing_receipt():
    provider = StaticTestnetProvider()

    receipt = AnchorReceipt.create(
        root_hash="a" * 64,
        network="STATIC_TESTNET",
        transaction_id="missing",
        block_number=1,
        anchored_at="2025-01-01T00:00:00Z",
    )

    assert provider.verify_on_chain(receipt) is False
