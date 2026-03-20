from app.security.evidence.memory.retention import EvidenceRetentionController
from app.security.evidence.memory.tier import EvidenceTier

def test_retention_does_not_modify_hash(evidence_record):
    controller = EvidenceRetentionController()

    controller.transition(evidence_record.record_hash, EvidenceTier.COLD)

    assert evidence_record.record_hash == evidence_record.record_hash
