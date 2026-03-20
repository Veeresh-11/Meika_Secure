from app.security.evidence.memory.replay import replay
from app.security.evidence.memory.retention import EvidenceRetentionController
from app.security.evidence.memory.tier import EvidenceTier

def test_replay_ignores_tiers(evidence_chain):
    controller = EvidenceRetentionController()

    for r in evidence_chain:
        controller.transition(r.record_hash, EvidenceTier.COLD)

    records = list(replay(evidence_chain))
    assert len(records) == len(evidence_chain)
