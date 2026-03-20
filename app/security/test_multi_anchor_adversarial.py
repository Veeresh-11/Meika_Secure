# app/security/test_multi_anchor_adversarial.py

from app.security.track_d.anchoring.multi_anchor_client import MultiAnchorClient
from app.security.track_d.anchoring.anchor_providers.static_provider import StaticTestnetProvider
from app.security.track_d.anchoring.anchor_providers.base_provider import BaseAnchorProvider
from app.security.track_d.anchoring.anchor_receipt import AnchorReceipt


class MaliciousProvider(BaseAnchorProvider):

    def network_id(self) -> str:
        return "EVIL_CHAIN"

    def submit_root(self, root_hash: str):
        raise RuntimeError("Malicious failure")

    def verify_on_chain(self, receipt: AnchorReceipt) -> bool:
        return False


def test_multi_anchor_with_malicious_provider():
    providers = [
        StaticTestnetProvider(),
        StaticTestnetProvider(),
        MaliciousProvider(),
    ]

    multi = MultiAnchorClient(providers, minimum_success=2)

    receipts = multi.anchor("root_hash")

    assert len(receipts) == 2
    assert multi.verify(receipts) is True
