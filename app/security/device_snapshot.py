"""
TRACK_A_CORE — Immutable Device Snapshot
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class DeviceSnapshot:

    device_id: str
    registered: bool = False
    state: Optional[str] = None

    # ---- Hardware & identity binding ----
    hardware_backed: bool = False
    attestation_verified: bool = False
    binding_valid: bool = False
    secure_boot: bool = False

    # ---- Replay & compromise signals ----
    replay_detected: bool = False
    compromised: bool = False
    clone_confirmed: bool = False

    # -----------------------------------------------------
    # FIX: context conversion (dict + object support)
    # -----------------------------------------------------
    @staticmethod
    def from_context(ctx) -> "DeviceSnapshot":

        if isinstance(ctx, dict):
            return DeviceSnapshot(
                device_id=ctx.get("device_id"),
                registered=ctx.get("registered", False),
                state=ctx.get("state"),
                hardware_backed=ctx.get("hardware_backed", False),
                attestation_verified=ctx.get("attestation_verified", False),
                binding_valid=ctx.get("binding_valid", False),
                secure_boot=ctx.get("secure_boot", False),
                replay_detected=ctx.get("replay_detected", False),
                compromised=ctx.get("compromised", False),
                clone_confirmed=ctx.get("clone_confirmed", False),
            )

        identity = getattr(ctx, "identity", None)
        posture = getattr(ctx, "posture", None)

        return DeviceSnapshot(
    device_id=getattr(ctx, "device_id"),
    registered=getattr(ctx, "registered", False),
    state=getattr(ctx, "state", None),

    hardware_backed=(
        identity.hardware_backed
        if identity is not None
        else getattr(ctx, "hardware_backed", False)
    ),

    attestation_verified=(
        identity.attestation_verified
        if identity is not None
        else getattr(ctx, "attestation_verified", False)
    ),

    binding_valid=(
        identity.binding_valid
        if identity is not None
        else getattr(ctx, "binding_valid", False)
    ),

    replay_detected=(
        identity.replay_detected
        if identity is not None
        else getattr(ctx, "replay_detected", False)
    ),

    clone_confirmed=(
        identity.clone_confirmed
        if identity is not None
        else getattr(ctx, "clone_confirmed", False)
    ),

    secure_boot=(
        posture.secure_boot
        if posture is not None
        else getattr(ctx, "secure_boot", False)
    ),

    compromised=(
        posture.compromised
        if posture is not None
        else getattr(ctx, "compromised", False)
    ),
)

    # -----------------------------------------------------
    # FIX: required for evidence engine
    # -----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "registered": self.registered,
            "state": self.state,
            "hardware_backed": self.hardware_backed,
            "attestation_verified": self.attestation_verified,
            "binding_valid": self.binding_valid,
            "secure_boot": self.secure_boot,
            "replay_detected": self.replay_detected,
            "compromised": self.compromised,
            "clone_confirmed": self.clone_confirmed,
        }