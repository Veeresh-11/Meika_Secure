import pytest
import jwt
import time

from app.security.federation.service import FederationService
from app.security.federation.verifier import TokenReplayVerifier
from app.security.pipeline import SecureIDKernel
from app.security.federation.keys import SigningKeyRegistry
from dataclasses import replace

def _setup():
    kernel = SecureIDKernel()
    registry = SigningKeyRegistry()
    registry.generate_and_register()

    service = FederationService(kernel, registry)
    verifier = TokenReplayVerifier(kernel, registry)

    ctx = kernel._default_context()

    return service, verifier, ctx


# -------------------------------------------------
# 1️⃣ Replay Attack
# -------------------------------------------------
def test_replay_attack_blocked():
    service, verifier, ctx = _setup()

    token = service.issue_token(ctx, "client-1")

    verifier.verify(token, "client-1", ctx)

    with pytest.raises(Exception):
        verifier.verify(token, "client-1", ctx)


# -------------------------------------------------
# 2️⃣ Expired Token
# -------------------------------------------------
def test_expired_token_rejected():
    service, verifier, ctx = _setup()

    token = service.issue_token(ctx, "client-1", ttl=1)

    time.sleep(2)

    with pytest.raises(Exception):
        verifier.verify(token, "client-1", ctx)


# -------------------------------------------------
# 3️⃣ Wrong Audience
# -------------------------------------------------
def test_wrong_audience_rejected():
    service, verifier, ctx = _setup()

    token = service.issue_token(ctx, "client-1")

    with pytest.raises(Exception):
        verifier.verify(token, "attacker-app")


# -------------------------------------------------
# 4️⃣ Tampered Token
# -------------------------------------------------
def test_token_tampering_detected():
    service, verifier, ctx = _setup()

    token = service.issue_token(ctx, "client-1")

    # Split token
    header, payload, signature = token.split(".")

    # Decode payload
    import base64
    import json

    padded = payload + "=" * (-len(payload) % 4)
    decoded = json.loads(base64.urlsafe_b64decode(padded))

    # 🔥 Tamper critical field
    decoded["sub"] = "attacker"

    # Re-encode payload WITHOUT resigning
    tampered_payload = base64.urlsafe_b64encode(
        json.dumps(decoded, separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=")

    tampered_token = f"{header}.{tampered_payload}.{signature}"

    with pytest.raises(Exception):
        verifier.verify(tampered_token, "client-1")


# -------------------------------------------------
# 5️⃣ Wrong Key Attack
# -------------------------------------------------
def test_wrong_key_rejected():
    kernel = SecureIDKernel()

    registry1 = SigningKeyRegistry()
    registry1.generate_and_register()

    registry2 = SigningKeyRegistry()
    registry2.generate_and_register()

    service = FederationService(kernel, registry1)
    verifier = TokenReplayVerifier(kernel, registry2)

    ctx = kernel._default_context()

    token = service.issue_token(ctx, "client-1")

    with pytest.raises(Exception):
        verifier.verify(token, "client-1", ctx)


# -------------------------------------------------
# 6️⃣ Missing Claims Attack
# -------------------------------------------------
def test_missing_claims_rejected():
    service, verifier, ctx = _setup()

    token = service.issue_token(ctx, "client-1")

    decoded = jwt.decode(token, options={"verify_signature": False})
    del decoded["jti"]

    forged = jwt.encode(decoded, "fake", algorithm="HS256")

    with pytest.raises(Exception):
        verifier.verify(forged, "client-1")
        
def test_device_binding_enforced():
    service, verifier, ctx = _setup()

    # ✅ ensure device is present
    ctx = replace(ctx, device_id="legit-device")

    token = service.issue_token(ctx, "client-1")

    # attacker uses different device
    attacker_ctx = replace(ctx, device_id="attacker-device")

    with pytest.raises(Exception):
        verifier.verify(token, "client-1", attacker_ctx)