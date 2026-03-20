from dataclasses import dataclass
from datetime import datetime

@dataclass
class WebAuthnCredential:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    hardware_backed: bool
    attestation_verified: bool
    attestation_type: str
    created_at: datetime
    last_used_at: datetime
    revoked: bool = False

