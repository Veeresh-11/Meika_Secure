class AuthorizationReceiptVerifier:

    def __init__(self, public_key):

        self.public_key = public_key

    def verify(self, receipt):

        digest = receipt.digest()

        return self.public_key.verify(
            digest,
            receipt.signature
        )
