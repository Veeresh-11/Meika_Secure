# app/security/federation/verifier.py
import hashlib
import base64

from app.security.version import KERNEL_VERSION, KERNEL_BUILD_HASH
from app.security.runtime_state import KernelState
from app.security.federation.pq_signer import PostQuantumSigner
def _get_jwt():
    try:
        import jwt
        return jwt
    except ImportError:
        raise RuntimeError("jwt is required for federation verification")

class TokenVerificationError(Exception):
    pass


class TokenReplayVerifier:

    def __init__(self, kernel, key_registry):
        self.kernel = kernel
        self.keys = key_registry
        self.pq = PostQuantumSigner()

    def verify(self, token: str, audience: str) -> dict:

        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        if not kid:
            raise TokenVerificationError("Missing kid")

        key = self.keys.get(kid)
        jwt = _get_jwt()
        claims = jwt.decode(
            token,
            key.public_key,
            algorithms=["EdDSA"],
            audience=audience,
            options={"verify_exp": False},
        )

        # -------------------------------------------------
        # Kernel invariants
        # -------------------------------------------------
        if claims["kernel_version"] != KERNEL_VERSION:
            raise TokenVerificationError("Kernel version mismatch")

        if claims["build_hash"] != KERNEL_BUILD_HASH:
            raise TokenVerificationError("Build hash mismatch")

        if self.kernel._state == KernelState.SAFE_MODE:
            raise TokenVerificationError("Kernel in SAFE_MODE")

        # -------------------------------------------------
        # PQ Signature Verification
        # -------------------------------------------------
        pq_sig = claims.get("pq_sig")
        binding_hash_b64 = claims.get("binding_hash")

        if pq_sig and binding_hash_b64:
            binding_hash = base64.urlsafe_b64decode(
                binding_hash_b64 + "=="
            )

            if not self.pq.verify(binding_hash, pq_sig):
                raise TokenVerificationError("PQ signature invalid")

        # -------------------------------------------------
        # Evidence existence
        # -------------------------------------------------
        evidence_hash = claims.get("evidence_hash")
        if not evidence_hash:
            raise TokenVerificationError("Missing evidence hash")

        store = self.kernel.evidence_store

        if hasattr(store, "get_all"):
            records = store.get_all()
        elif hasattr(store, "_records"):
            records = sorted(
                store._records.values(),
                key=lambda r: r.sequence_number,
            )
        else:
            raise TokenVerificationError("Unsupported evidence store")

        if evidence_hash not in [r.record_hash for r in records]:
            raise TokenVerificationError("Evidence hash not found")

        # Chain continuity only
        previous = None
        for r in records:
            if previous and r.previous_hash != previous:
                raise TokenVerificationError("Chain broken")
            previous = r.record_hash

        return claims
