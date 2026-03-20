# app/security/evidence/anchor_bridge.py

from typing import List, Dict, Any

from app.security.evidence.models import EvidenceRecord
from app.security.evidence.seal_service import EvidenceSealService
from app.security.evidence.engine import build_anchor_record


class EvidenceAnchorBridge:

    def __init__(self, anchor_client):
        self._seal_service = EvidenceSealService()
        self._anchor_client = anchor_client

    # ---------------------------------------------------------

    def _anchor(self, root_hash: str, record_count: int) -> Any:

        try:
            return self._anchor_client.anchor(root_hash)
        except TypeError:
            payload = {
                "root_hash": root_hash,
                "record_count": record_count,
            }
            return self._anchor_client.anchor(payload)

    # ---------------------------------------------------------

    def seal_and_anchor(self, records: List[EvidenceRecord]) -> Dict:

        seal = self._seal_service.seal(records)

        root_hash = seal["snapshot"]["root_hash"]
        record_count = seal["snapshot"]["record_count"]

        anchor_receipt = self._anchor(root_hash, record_count)

        return {
            "seal": seal,
            "anchor_receipt": anchor_receipt,
        }

    # ---------------------------------------------------------

    def seal_anchor_and_record(
        self,
        records: List[EvidenceRecord],
        store,
        context=None,   # unused
    ) -> Dict:

        result = self.seal_and_anchor(records)

        root_hash = result["seal"]["snapshot"]["root_hash"]
        record_count = result["seal"]["snapshot"]["record_count"]

        record = build_anchor_record(
            root_hash=root_hash,
            record_count=record_count,
            anchor_receipt=result["anchor_receipt"],
            store=store,
        )

        store.append(record)

        return result
