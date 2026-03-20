from dataclasses import dataclass
from datetime import datetime
from typing import Optional


# --- Identity / key / attestation state ---
@dataclass(frozen=True)
class DeviceIdentityContext:
    hardware_backed: bool
    attestation_verified: bool
    binding_valid: bool
    clone_confirmed: bool
    replay_detected: bool
    last_attested_at: Optional[datetime]


# --- Runtime posture ---
@dataclass(frozen=True)
class DevicePostureContext:
    secure_boot: bool
    compromised: bool


# --- Top-level device context ---
@dataclass(frozen=True)
class DeviceContext:
    device_id: str
    registered: bool
    state: str  # "active" | "revoked"

    identity: DeviceIdentityContext
    posture: DevicePostureContext

