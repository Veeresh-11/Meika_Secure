import hashlib

from app.security.receipts.models import AuthorizationReceipt


class AuthorizationReceiptGenerator:

    def __init__(self, signer):
        self.signer = signer

    def generate(self, context, decision, evidence_hash, merkle_root):

        subject = context.principal_id
        action = context.intent
        resource = context.metadata.get("resource")

        context_hash = hashlib.sha256(
            str(context.to_dict()).encode("utf-8")
        ).hexdigest()

        receipt = AuthorizationReceipt(
            subject=subject,
            action=action,
            resource=resource,
            decision=decision.outcome.name,
            policy_version=decision.policy_version,
            timestamp=context.request_time.isoformat(),
            context_hash=context_hash,
            evidence_hash=evidence_hash,
            merkle_root=merkle_root,
        )

        digest = receipt.digest()

        receipt.signature = self.signer.sign(digest)

        return receipt
