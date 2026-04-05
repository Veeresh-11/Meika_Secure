import hashlib
import base64
import time

from app.security.version import KERNEL_VERSION, KERNEL_BUILD_HASH
from app.security.runtime_state import KernelState
from app.security.federation.pq_signer import PostQuantumSigner
from app.security.federation.replay_store import (
    InMemoryReplayStore,
    ReplayAttackDetected,
)
from app.security.federation.revocation_store import InMemoryRevocationStore
from app.security.risk_engine import RiskEngine, RiskLevel


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
        self.risk_engine = RiskEngine()

        # Replay store (Redis fallback)
        try:
            from app.security.federation.replay_store_redis import RedisReplayStore
            self.replay_store = RedisReplayStore()
        except Exception:
            self.replay_store = InMemoryReplayStore()

        # Revocation store (Redis fallback)
        try:
            from app.security.federation.revocation_store_redis import RedisRevocationStore
            self.revocation_store = RedisRevocationStore()
        except Exception:
            self.revocation_store = InMemoryRevocationStore()

    def _compute_device_hash(self, context):
        return hashlib.sha256(str(context.device_id).encode()).hexdigest()

    def revoke_token(self, jti: str, exp: int):
        self.revocation_store.revoke(jti, exp)

    # -------------------------------------------------
    # MAIN VERIFY
    # -------------------------------------------------
    def verify(self, token: str, audience: str, context=None) -> dict:
        jwt = _get_jwt()

        # 1️⃣ HEADER
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg")

        if not kid:
            raise TokenVerificationError("Missing kid")

        if alg != "EdDSA":
            raise TokenVerificationError("Invalid algorithm")

        # 2️⃣ KEY
        key = self.keys.get(kid)

        if not key:
            raise TokenVerificationError("Unknown key")

        if getattr(key, "revoked", False):
            raise TokenVerificationError("Key revoked")

        # 3️⃣ CLAIMS
        claims = jwt.decode(
            token,
            key.public_key,
            algorithms=["EdDSA"],
            audience=audience,
            issuer="meika-authority",
            options={"require": ["exp", "iat", "aud", "iss", "jti"]},
        )

        # 4️⃣ TIME
        now = int(time.time())
        if claims["iat"] > now + 60:
            raise TokenVerificationError("Token issued in future")

        # 5️⃣ TYPE
        if claims.get("typ") != "access":
            raise TokenVerificationError("Invalid token type")

        # 6️⃣ DEVICE
        device_hash = claims.get("device_state_hash")

        if device_hash:
            if not context:
                raise TokenVerificationError("Missing context for device verification")

            expected = self._compute_device_hash(context)

            if device_hash != expected:
                raise TokenVerificationError("Device mismatch")

        # 7️⃣ REPLAY
        jti = claims.get("jti")
        exp = claims.get("exp")

        if not jti or not exp:
            raise TokenVerificationError("Missing jti or exp")

        try:
            self.replay_store.check_and_store(jti, exp)
        except Exception:
            raise TokenVerificationError("Replay attack detected")

        # 8️⃣ REVOCATION
        if self.revocation_store.is_revoked(jti):
            raise TokenVerificationError("Token revoked")

        # 9️⃣ KERNEL
        if claims["kernel_version"] != KERNEL_VERSION:
            raise TokenVerificationError("Kernel version mismatch")

        if claims["build_hash"] != KERNEL_BUILD_HASH:
            raise TokenVerificationError("Build hash mismatch")

        if self.kernel._state == KernelState.SAFE_MODE:
            raise TokenVerificationError("Kernel in SAFE_MODE")

        # 🔟 PQ
        pq_sig = claims.get("pq_sig")
        binding_hash_b64 = claims.get("binding_hash")

        if pq_sig and binding_hash_b64:
            binding_hash = base64.urlsafe_b64decode(binding_hash_b64 + "==")

            if not self.pq.verify(binding_hash, pq_sig):
                raise TokenVerificationError("PQ signature invalid")

        # 11️⃣ EVIDENCE
        evidence_hash = claims.get("evidence_hash")

        if not evidence_hash:
            raise TokenVerificationError("Missing evidence hash")

        store = self.kernel.evidence_store

        if hasattr(store, "get_all"):
            records = store.get_all()
        elif hasattr(store, "_records"):
            records = sorted(store._records.values(), key=lambda r: r.sequence_number)
        else:
            raise TokenVerificationError("Unsupported evidence store")

        if evidence_hash not in [r.record_hash for r in records]:
            raise TokenVerificationError("Evidence hash not found")

        prev = None
        for r in records:
            if prev and r.previous_hash != prev:
                raise TokenVerificationError("Chain broken")
            prev = r.record_hash

        # 12️⃣ RISK ENGINE ✅ (CORRECTLY INSIDE FUNCTION)
        risk = self.risk_engine.assess(context, claims)

        if risk == RiskLevel.HIGH:
            raise TokenVerificationError("High risk request blocked")
        elif risk == RiskLevel.MEDIUM:
            claims["risk"] = "medium"
        else:
            claims["risk"] = "low"

        if context:
            self.risk_engine.register_device(context)

        return claims