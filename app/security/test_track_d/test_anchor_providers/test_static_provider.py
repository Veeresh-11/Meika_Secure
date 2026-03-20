from app.security.track_d.anchoring.anchor_providers.static_provider import (
    StaticTestnetProvider,
)


def test_static_anchor_and_verify():

    provider = StaticTestnetProvider()

    receipt = provider.submit_root("root-abc")

    assert provider.verify_on_chain(receipt) is True
    assert receipt.network == "STATIC_TESTNET"
