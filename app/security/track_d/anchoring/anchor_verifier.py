from __future__ import annotations

from .anchor_receipt import AnchorReceipt
from .anchor_client import AnchorClient


class AnchorVerifier:

    def __init__(self, client: AnchorClient):
        self.client = client

    def verify(self, receipt: AnchorReceipt) -> bool:

        receipt.verify_integrity()

        if not self.client.verify(receipt):
            raise ValueError("External network verification failed")

        return True
