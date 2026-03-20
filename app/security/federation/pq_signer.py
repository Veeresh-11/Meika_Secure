# app/security/federation/pq_signer.py

import hashlib
import base64


class PostQuantumSigner:
    """
    Deterministic mock PQ signer.
    Replace with ML-DSA-65 later.
    """

    def __init__(self, secret: bytes = b"meika-pq-root"):
        self._secret = secret

    def sign(self, message: bytes) -> str:
        digest = hashlib.sha3_256(self._secret + message).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def verify(self, message: bytes, signature: str) -> bool:
        expected = self.sign(message)
        return expected == signature
