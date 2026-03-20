from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone


def _parse_utc(ts: str) -> datetime:
    if not ts.endswith("Z"):
        raise ValueError("Timestamp must be RFC3339 UTC (Z suffix required)")
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _canonical(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class AnchorReceipt:

    root_hash: str
    network: str
    transaction_id: str
    block_number: int
    anchored_at: str
    receipt_hash: str

    def to_dict(self):
        return {
            "root_hash": self.root_hash,
            "network": self.network,
            "transaction_id": self.transaction_id,
            "block_number": self.block_number,
            "anchored_at": self.anchored_at,
            "receipt_hash": self.receipt_hash,
        }

    @staticmethod
    def create(
        *,
        root_hash: str,
        network: str,
        transaction_id: str,
        block_number: int,
        anchored_at: str,
    ) -> "AnchorReceipt":

        _parse_utc(anchored_at)

        data = {
            "root_hash": root_hash,
            "network": network,
            "transaction_id": transaction_id,
            "block_number": block_number,
            "anchored_at": anchored_at,
        }

        receipt_hash = hashlib.sha256(_canonical(data)).hexdigest()

        return AnchorReceipt(
            root_hash=root_hash,
            network=network,
            transaction_id=transaction_id,
            block_number=block_number,
            anchored_at=anchored_at,
            receipt_hash=receipt_hash,
        )

    def verify_integrity(self) -> bool:

        data = {
            "root_hash": self.root_hash,
            "network": self.network,
            "transaction_id": self.transaction_id,
            "block_number": self.block_number,
            "anchored_at": self.anchored_at,
        }

        expected = hashlib.sha256(_canonical(data)).hexdigest()

        if expected != self.receipt_hash:
            raise ValueError("Anchor receipt tampering detected")

        return True
