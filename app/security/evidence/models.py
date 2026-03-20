# app/security/evidence/models.py
"""
TRACK B — Evidence Record Model
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceRecord:
    sequence_number: int
    previous_hash: str
    payload_hash: str
    record_hash: str
