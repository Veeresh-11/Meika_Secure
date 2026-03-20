from dataclasses import dataclass
import hashlib


@dataclass(frozen=True)
class MigrationManifest:
    migration_id: str
    from_version: str
    to_version: str
    migration_hash: str
    signed_by: str

    def fingerprint(self) -> str:
        canonical = (
            f"{self.migration_id}|"
            f"{self.from_version}|"
            f"{self.to_version}|"
            f"{self.migration_hash}|"
            f"{self.signed_by}"
        )
        return hashlib.sha256(canonical.encode()).hexdigest()
