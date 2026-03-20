"""
TRACK_A_CORE — Immutable Device Snapshot

This module defines DeviceSnapshot, the frozen representation of a device's
security posture at request evaluation time.

Design principles:
- No live device access
- No mutation after creation
- Deterministic, serializable state
- Safe against TOCTOU and replay attacks

If a device attribute is not captured here, it does not exist for enforcement.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class DeviceSnapshot:
    """
    Immutable device security snapshot.

    Sprint A2 invariants:
    - Device state is frozen at request time
    - Snapshot is immutable and audit-safe
    - Snapshot is the ONLY device input to the kernel
    """

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

    @staticmethod
    def from_context(ctx) -> "DeviceSnapshot":
        """
        Construct a snapshot from a trusted, pre-validated context.

        NOTE:
        - This is a convenience helper.
        - Kernel enforcement MUST rely only on the resulting snapshot,
          never on the original context.
        """
        return DeviceSnapshot(
            device_id=ctx.device_id,
            registered=getattr(ctx, "registered", False),
            state=getattr(ctx, "state", None),
            hardware_backed=getattr(ctx, "hardware_backed", False),
            attestation_verified=getattr(ctx, "attestation_verified", False),
            binding_valid=getattr(ctx, "binding_valid", False),
            secure_boot=getattr(ctx, "secure_boot", False),
            replay_detected=getattr(ctx, "replay_detected", False),
            compromised=getattr(ctx, "compromised", False),
            clone_confirmed=getattr(ctx, "clone_confirmed", False),
        )

    def to_dict(self) -> dict:
        """
        Deterministic, audit-safe serialization.

        Used for:
        - Evidence hashing
        - Policy sanity checks
        - Determinism verification
        """
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
