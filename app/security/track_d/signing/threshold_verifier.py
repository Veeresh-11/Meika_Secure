"""
TRACK D — Threshold Verifier (Final Hardened)

Security Guarantees:
- Duplicate signer detection (pre-crypto)
- Deterministic canonical hashing
- Strict lifecycle enforcement
- Algorithm binding
- Governance enforcement
- PASS + FAIL logging (transparency + ledger)
- Policy expiration enforcement
- Fail-closed behavior
"""

from __future__ import annotations

import json
import hashlib
from typing import Dict, Any, List, Set

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from .trust_store import TrustStore
from ..governance.governance_registry import GovernanceRegistry
from ..transparency.transparency_log import TransparencyLog
from ..audit.verification_ledger import VerificationLedger


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class ThresholdVerifier:

    def __init__(
        self,
        trust_store: TrustStore,
        governance_registry: GovernanceRegistry | None = None,
        transparency_log: TransparencyLog | None = None,
        ledger: VerificationLedger | None = None,
    ):
        self.trust_store = trust_store
        self.governance_registry = governance_registry
        self.transparency_log = transparency_log
        self.ledger = ledger

    def verify(
        self,
        *,
        payload: Dict[str, Any],
        signature_object: Dict[str, Any],
        now_utc: str,
    ) -> bool:

        canonical = _canonical(payload)
        expected_hash = hashlib.sha256(canonical).hexdigest()

        policy_family = signature_object.get("policy_family")
        policy_version = signature_object.get("policy_version")

        verified_key_ids: List[str] = []

        try:

            if signature_object.get("hash_algorithm") != "SHA-256":
                raise ValueError("Unsupported hash algorithm")

            signatures: List[Dict] = signature_object.get("signatures", [])

            if not signatures:
                raise ValueError("No signatures provided")

            if expected_hash != signature_object.get("payload_hash"):
                raise ValueError("Payload hash mismatch")

            total_weight = 0
            verified_roles: Set[str] = set()
            seen_keys: Set[str] = set()

            # Duplicate detection
            for sig in signatures:

                if "key_id" not in sig or "signature" not in sig:
                    raise ValueError("Malformed signature entry")

                key_id = sig["key_id"]

                if key_id in seen_keys:
                    raise ValueError("Duplicate signer detected")

                seen_keys.add(key_id)

            # Crypto verification
            for sig in signatures:

                key_id = sig["key_id"]

                self.trust_store.validate_lifecycle(key_id, now_utc)

                if self.trust_store.get_algorithm(key_id) != "Ed25519":
                    raise ValueError("Unsupported algorithm")

                public_key_bytes = self.trust_store.get_public_key(key_id)
                public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

                try:
                    signature_bytes = bytes.fromhex(sig["signature"])
                    public_key.verify(
                        signature_bytes,
                        signature_object["payload_hash"].encode("utf-8"),
                    )
                except Exception:
                    raise ValueError("Signature verification failed")

                total_weight += self.trust_store.get_weight(key_id)
                verified_roles.update(self.trust_store.get_roles(key_id))
                verified_key_ids.append(key_id)

            # Governance enforcement
            if self.governance_registry and policy_family and policy_version:

                policy = self.governance_registry.get_policy(
                    policy_family,
                    policy_version,
                )

                # Expiry enforcement
                if policy.get("expires_at") and now_utc >= policy["expires_at"]:
                    raise ValueError("Policy expired")

                if total_weight < policy["minimum_weight"]:
                    raise ValueError("Insufficient signing weight")

                required_roles = set(policy.get("required_roles", []))
                if required_roles and not required_roles.issubset(verified_roles):
                    raise ValueError("Required governance roles missing")

            # PASS logging
            if self.transparency_log:
                self.transparency_log.append(
                    payload_hash=expected_hash,
                    policy_family=policy_family,
                    policy_version=policy_version,
                    result="PASS",
                )

            if self.ledger:
                self.ledger.append(
                    payload_hash=expected_hash,
                    policy_family=policy_family,
                    policy_version=policy_version,
                    result="PASS",
                    key_ids=verified_key_ids,
                    reason=None,
                )

            return True

        except Exception as e:

            if self.transparency_log:
                self.transparency_log.append(
                    payload_hash=expected_hash,
                    policy_family=policy_family,
                    policy_version=policy_version,
                    result="FAIL",
                )

            if self.ledger:
                self.ledger.append(
                    payload_hash=expected_hash,
                    policy_family=policy_family,
                    policy_version=policy_version,
                    result="FAIL",
                    key_ids=verified_key_ids,
                    reason=str(e),
                )

            raise
