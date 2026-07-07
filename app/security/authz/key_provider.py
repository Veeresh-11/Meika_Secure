import os


class KeyProvider:
    """
    Centralized signing key provider.

    Future implementations may retrieve keys from:
      - TPM
      - HSM
      - Azure Key Vault
      - AWS KMS
      - HashiCorp Vault
    """

    @staticmethod
    def signing_key() -> str:
        key = os.getenv("MEIKA_SIGNING_KEY")

        if not key:
            raise RuntimeError(
                "MEIKA_SIGNING_KEY is not configured."
            )

        return key