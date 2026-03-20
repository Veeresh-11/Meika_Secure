from __future__ import annotations

from .anchor_client import AnchorClient
from .anchor_receipt import AnchorReceipt
from datetime import datetime, timezone


class MockAnchorClient(AnchorClient):

    def __init__(self):
        self._ledger = {}
        self._by_root = {}

    def anchor(self, root_hash: str) -> AnchorReceipt:

        anchored_at = (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

        receipt = AnchorReceipt.create(
            root_hash=root_hash,
            network="mocknet",
            transaction_id=f"tx-{root_hash}",
            block_number=len(self._ledger) + 1,
            anchored_at=anchored_at,
        )

        self._ledger[receipt.transaction_id] = receipt
        self._by_root[root_hash] = receipt

        return receipt

    def verify(self, receipt: AnchorReceipt) -> bool:

        stored = self._ledger.get(receipt.transaction_id)
        if not stored:
            return False

        # Verify internal integrity
        receipt.verify_integrity()

        return stored.receipt_hash == receipt.receipt_hash

    # Public verify layer

    def get_receipt(self, root_hash: str):
        return self._by_root.get(root_hash)

    def verify_receipt(self, receipt: AnchorReceipt):
        return self.verify(receipt)
