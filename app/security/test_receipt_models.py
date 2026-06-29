import hashlib
import json

from app.security.receipts.models import AuthorizationReceipt


def build_receipt():

    return AuthorizationReceipt(
        subject="user1",
        action="read",
        resource="document-1",
        decision="ALLOW",
        policy_version="v1",
        timestamp="2026-01-01T00:00:00",
        context_hash="ctxhash",
        evidence_hash="evhash",
        merkle_root="roothash",
    )


def test_canonical_output():

    receipt = build_receipt()

    canonical = receipt.canonical()

    payload = json.loads(canonical)

    assert payload["subject"] == "user1"
    assert payload["action"] == "read"
    assert payload["resource"] == "document-1"
    assert payload["decision"] == "ALLOW"
    assert payload["policy_version"] == "v1"
    assert payload["context_hash"] == "ctxhash"
    assert payload["evidence_hash"] == "evhash"
    assert payload["merkle_root"] == "roothash"


def test_digest_matches_sha256():

    receipt = build_receipt()

    expected = hashlib.sha256(
        receipt.canonical().encode("utf-8")
    ).hexdigest()

    assert receipt.digest() == expected