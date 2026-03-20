from dataclasses import dataclass
import hashlib


@dataclass(frozen=True)
class SchemaVersion:
    version: str
    schema_hash: str
    minimum_compatible: str

    def fingerprint(self) -> str:
        canonical = f"{self.version}|{self.schema_hash}|{self.minimum_compatible}"
        return hashlib.sha256(canonical.encode()).hexdigest()
