# app/security/federation/service.py

def _get_jwt():
    try:
        import jwt
        return jwt
    except ImportError:
        raise RuntimeError("jwt is required for federation")
    
import hashlib
import time
import base64
import json

from app.security.version import KERNEL_VERSION, KERNEL_BUILD_HASH
from app.security.runtime_state import KernelState
from app.security.pipeline import SecureIDKernel
from app.security.federation.pq_signer import PostQuantumSigner


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class FederationService:

    def __init__(self, kernel: SecureIDKernel, key_registry):
        self.kernel = kernel
        self.keys = key_registry
        self.pq = PostQuantumSigner()

    def issue_token(self, context, audience: str, ttl: int = 3600) -> str:

        if self.kernel._state == KernelState.SAFE_MODE:
            raise Exception("Cannot issue token in SAFE_MODE")

        decision = self.kernel.evaluate(context)

        if decision.outcome.name != "ALLOW":
            raise Exception("Cannot issue token on DENY")

        if not decision.evidence_hash:
            raise Exception("Evidence hash missing")

        now = int(time.time())
        exp = now + ttl

        jti_input = (
            context.principal_id
            + decision.evidence_hash
            + str(now)
        ).encode()

        jti = hashlib.sha256(jti_input).hexdigest()

        payload = {
            "iss": "meika-authority",
            "sub": context.principal_id,
            "aud": audience,
            "iat": now,
            "exp": exp,
            "kernel_version": KERNEL_VERSION,
            "build_hash": KERNEL_BUILD_HASH,
            "policy_version": decision.policy_version,
            "evidence_hash": decision.evidence_hash,
            "device_state_hash": hashlib.sha256(
                str(context.device_id).encode()
            ).hexdigest() if context.device_id else None,
            "jti": jti,
        }

        key = self.keys.get_active()

        header = {
            "alg": "EdDSA",
            "kid": key.kid,
            "typ": "JWT",
        }

        # -------------------------------------------------
        # 1️⃣ Deterministic unsigned JWT construction
        # -------------------------------------------------
        header_b64 = b64url(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
        )

        payload_b64 = b64url(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )

        signing_input = f"{header_b64}.{payload_b64}".encode()

        # -------------------------------------------------
        # 2️⃣ SHA3 binding + PQ signature
        # -------------------------------------------------
        binding_hash = hashlib.sha3_256(signing_input).digest()
        pq_signature = self.pq.sign(binding_hash)

        payload["pq_sig"] = pq_signature
        payload["pq_alg"] = "ML-DSA-65"
        payload["binding_hash"] = b64url(binding_hash)

        # -------------------------------------------------
        # 3️⃣ Final Ed25519 signature
        # -------------------------------------------------
        jwt = _get_jwt()
        token = jwt.encode(
            payload,
            key.private_key,
            algorithm="EdDSA",
            headers={"kid": key.kid},
        )

        return token
