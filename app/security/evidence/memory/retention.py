# app/security/evidence/memory/retention.py

from app.security.evidence.memory.tier import EvidenceTier

class EvidenceRetentionController:
    """
    Track C — Retention Controller

    NON-AUTHORITATIVE:
    - Cannot delete evidence
    - Cannot mutate evidence
    - Cannot change hashes
    """

    def __init__(self):
        self._state = {}

    def get_tier(self, record_hash):
        return self._state.get(record_hash, EvidenceTier.HOT)

    def transition(self, record_hash, tier: EvidenceTier):
        self._state[record_hash] = tier
