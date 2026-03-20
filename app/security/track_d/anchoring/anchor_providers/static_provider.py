from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from .base_provider import BaseAnchorProvider
from ..anchor_receipt import AnchorReceipt


class StaticTestnetProvider(BaseAnchorProvider):

    def __init__(self):
        self._chain = {}

    def network_id(self) -> str:
        return "STATIC_TESTNET"

    def submit_root(self, root_hash: str) -> AnchorReceipt:

        block_number = len(self._chain) + 1
        anchored_at = (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

        receipt = AnchorReceipt.create(
            root_hash=root_hash,
            network=self.network_id(),
            transaction_id=f"static-{block_number}",
            block_number=block_number,
            anchored_at=anchored_at,
        )

        self._chain[receipt.transaction_id] = receipt
        return receipt

    def verify_on_chain(self, receipt: AnchorReceipt) -> bool:
        stored = self._chain.get(receipt.transaction_id)
        if not stored:
            return False
        return stored.receipt_hash == receipt.receipt_hash
