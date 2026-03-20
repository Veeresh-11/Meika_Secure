# app/security/evidence/memory/replay.py

from app.security.errors import SecurityInvariantViolation

def replay(records):
    """
    Deterministic Evidence Replay

    Validates:
    - Sequence order
    - previous_hash linkage
    - No gaps
    """

    previous = None

    for record in records:
        if previous:
            if demonstrated := record.previous_hash != previous.record_hash:
                raise SecurityInvariantViolation(
                    "EVIDENCE_REPLAY_CHAIN_BROKEN"
                )
        previous = record
        yield record
