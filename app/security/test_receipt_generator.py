from datetime import datetime
from types import SimpleNamespace

from app.security.receipts.generator import (
    AuthorizationReceiptGenerator,
)


class FakeSigner:

    def sign(self, digest):
        return f"signed:{digest}"


class FakeContext:

    principal_id = "user-1"
    intent = "read.file"
    request_time = datetime.utcnow()

    metadata = {
        "resource": "document-123"
    }

    def to_dict(self):
        return {
            "principal_id": self.principal_id,
            "intent": self.intent,
        }


class FakeContextNoResource:

    principal_id = "user-2"
    intent = "write.file"
    request_time = datetime.utcnow()

    metadata = {}

    def to_dict(self):
        return {
            "principal_id": self.principal_id,
            "intent": self.intent,
        }


class FakeDecision:

    outcome = SimpleNamespace(
        name="ALLOW"
    )

    policy_version = "v1"


def test_generate_receipt():

    signer = FakeSigner()

    generator = AuthorizationReceiptGenerator(
        signer
    )

    receipt = generator.generate(
        context=FakeContext(),
        decision=FakeDecision(),
        evidence_hash="evidence123",
        merkle_root="root123",
    )

    assert receipt.subject == "user-1"
    assert receipt.action == "read.file"
    assert receipt.resource == "document-123"

    assert receipt.decision == "ALLOW"

    assert receipt.evidence_hash == "evidence123"
    assert receipt.merkle_root == "root123"

    assert receipt.signature is not None


def test_generate_without_resource():

    signer = FakeSigner()

    generator = AuthorizationReceiptGenerator(
        signer
    )

    receipt = generator.generate(
        context=FakeContextNoResource(),
        decision=FakeDecision(),
        evidence_hash="evidence456",
        merkle_root="root456",
    )

    assert receipt.resource is None

    assert receipt.subject == "user-2"

    assert receipt.signature is not None


def test_signature_uses_digest():

    captured = {}

    class RecordingSigner:

        def sign(self, digest):
            captured["digest"] = digest
            return "sig"

    generator = AuthorizationReceiptGenerator(
        RecordingSigner()
    )

    receipt = generator.generate(
        context=FakeContext(),
        decision=FakeDecision(),
        evidence_hash="abc",
        merkle_root="xyz",
    )

    assert captured["digest"]
    assert receipt.signature == "sig"