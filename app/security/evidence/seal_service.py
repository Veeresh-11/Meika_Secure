# app/security/evidence/seal_service.py

from typing import List, Dict
from app.security.evidence.models import EvidenceRecord
from app.security.evidence.seal import create_seal_snapshot


class EvidenceSealService:
    """
    Infrastructure-safe sealing service.

    This does NOT mutate ledger.
    This does NOT anchor.
    This only computes and returns snapshot.
    """

    def seal(self, records: List[EvidenceRecord]) -> Dict:
        """
        Returns seal snapshot payload.
        """
        return create_seal_snapshot(records)
