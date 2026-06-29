from app.security.track_d.anchoring.anchor_client import AnchorClient


class DummyAnchorClient(AnchorClient):

    def anchor(self, root_hash: str):
        return super().anchor(root_hash)

    def verify(self, receipt):
        return super().verify(receipt)


def test_anchor_abstract_method_body():
    client = DummyAnchorClient()

    assert client.anchor("root") is None


def test_verify_abstract_method_body():
    client = DummyAnchorClient()

    assert client.verify("receipt") is None