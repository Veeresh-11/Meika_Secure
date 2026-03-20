# app/security/evidence/memory/cold.py

class ColdEvidenceStore:
    """
    Cold Evidence Archive

    SECURITY RULES:
    - Read-only
    - No rehashing
    - No reordering
    - No deletion
    """

    def __init__(self, reader):
        """
        reader must implement:
        - get(hash)
        - range(start, end)
        """
        self._reader = reader

    def get(self, record_hash):
        return self._reader.get(record_hash)

    def range(self, start, end):
        return self._reader.range(start, end)
