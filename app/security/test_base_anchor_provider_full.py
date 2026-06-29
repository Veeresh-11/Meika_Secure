from app.security.track_d.anchoring.anchor_providers.base_provider import (
    BaseAnchorProvider,
)


class DummyProvider(BaseAnchorProvider):

    def network_id(self):
        return super().network_id()

    def submit_root(self, root_hash):
        return super().submit_root(root_hash)

    def verify_on_chain(self, receipt):
        return super().verify_on_chain(receipt)


def test_network_id_abstract_body():
    provider = DummyProvider()

    assert provider.network_id() is None


def test_submit_root_abstract_body():
    provider = DummyProvider()

    assert provider.submit_root("root") is None


def test_verify_on_chain_abstract_body():
    provider = DummyProvider()

    assert provider.verify_on_chain("receipt") is None