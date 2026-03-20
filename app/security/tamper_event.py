from dataclasses import dataclass
from datetime import datetime
from app.security.version import KERNEL_VERSION, KERNEL_BUILD_HASH


@dataclass(frozen=True)
class TamperEvent:
    event_type: str
    kernel_version: str
    kernel_build_hash: str
    reason: str
    timestamp: str

    @staticmethod
    def create(reason: str) -> "TamperEvent":
        return TamperEvent(
            event_type="KERNEL_TAMPER_DETECTED",
            kernel_version=KERNEL_VERSION,
            kernel_build_hash=KERNEL_BUILD_HASH,
            reason=reason,
            timestamp=datetime.utcnow().isoformat(),
        )
