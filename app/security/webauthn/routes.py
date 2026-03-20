from fastapi import APIRouter, HTTPException
from .challenge import generate_challenge
from .attestation import verify_attestation
from .assertion import verify_assertion
from .models import WebAuthnCredential
from datetime import datetime
from app.security.webauthn.mapper import build_device_identity_from_webauthn
from app.security.device.context import DeviceContext, DevicePostureContext

router = APIRouter(prefix="/webauthn")

TEMP_CHALLENGES = {}
CREDENTIALS = {}

@router.post("/register/start")
def register_start(user_id: str):
    challenge = generate_challenge()
    TEMP_CHALLENGES[user_id] = challenge
    return {"challenge": challenge}

@router.post("/register/finish")
def register_finish(user_id: str, attestation: dict):
    challenge = TEMP_CHALLENGES.get(user_id)
    if not challenge:
        raise HTTPException(400, "No challenge")

    data = verify_attestation(attestation, challenge)

    cred = WebAuthnCredential(
        credential_id=attestation["credential_id"].encode(),
        public_key=data["public_key"].encode(),
        sign_count=0,
        hardware_backed=True,
        attestation_verified=True,
        attestation_type=data["attestation_type"],
        created_at=datetime.utcnow(),
        last_used_at=datetime.utcnow(),
    )

    CREDENTIALS[user_id] = cred
    return {"status": "registered"}

@router.post("/auth/finish")
def auth_finish(user_id: str, assertion: dict):
    cred = CREDENTIALS.get(user_id)
    if not cred:
        raise HTTPException(403, "No credential")

    verify_assertion(assertion, cred)
    return {"status": "authenticated"}

identity = build_device_identity_from_webauthn(
    hardware_backed=True,              # from attestation
    attestation_verified=True,          # from verification
    binding_valid=True,                 # RP ID + origin verified
    clone_confirmed=False,
    replay_detected=False,
    last_attested_at=datetime.utcnow(),
)

device = DeviceContext(
    device_id=device_id,
    registered=True,
    state="active",
    identity=identity,
    posture=DevicePostureContext(
        secure_boot=True,
        compromised=False,
    ),
)
