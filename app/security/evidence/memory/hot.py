# app/security/evidence/memory/hot.py

from app.security.evidence.store import InMemoryEvidenceStore

class HotEvidenceStore(InMemoryEvidenceStore):
    """
    HOT Evidence Store

    - Append-only
    - Hash-authoritative
    - Replayable
    - Kernel writes ONLY

    Track C rule:
    This store may disappear without affecting correctness.
    """
    pass
