"""
TRACK D — HSM Signer Stub

Enterprise integration layer.

Replace implementation with:
- PKCS#11
- CloudHSM
- Azure Key Vault
- AWS KMS
"""

from .signer_interface import ISigner


class HsmSigner(ISigner):

    def sign(self, data: bytes):
        raise NotImplementedError("HSM signing not configured")

    def algorithm(self) -> str:
        return "Ed25519-HSM"

    def key_id(self) -> str:
        raise NotImplementedError("HSM key_id retrieval not configured")
