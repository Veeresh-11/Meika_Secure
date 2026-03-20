import hashlib
import json
from dataclasses import dataclass


@dataclass
class AuthorizationReceipt:

    subject: str
    action: str
    resource: str
    decision: str
    policy_version: str
    timestamp: str
    context_hash: str
    evidence_hash: str
    merkle_root: str
    signature: str | None = None

    def canonical(self):

        payload = {
            "subject": self.subject,
            "action": self.action,
            "resource": self.resource,
            "decision": self.decision,
            "policy_version": self.policy_version,
            "timestamp": self.timestamp,
            "context_hash": self.context_hash,
            "evidence_hash": self.evidence_hash,
            "merkle_root": self.merkle_root,
        }

        return json.dumps(payload, sort_keys=True)

    def digest(self):

        return hashlib.sha256(
            self.canonical().encode("utf-8")
        ).hexdigest()
