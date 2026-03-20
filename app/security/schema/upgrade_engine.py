from app.security.schema.exceptions import SchemaUpgradeViolation
from app.security.evidence.engine import (
    build_governance_upgrade_record,
    append_evidence_record,
)
from app.security.schema.semver import SemanticVersion

class UpgradeEngine:

    def __init__(self, current_version: str, evidence_store=None):
        self.current_version = current_version
        self.evidence_store = evidence_store

    def validate_upgrade(self, manifest):

        if manifest.from_version != self.current_version:
            raise SchemaUpgradeViolation("INVALID_FROM_VERSION")

        current = SemanticVersion.parse(self.current_version)
        target = SemanticVersion.parse(manifest.to_version)

        if target <= current:
            raise SchemaUpgradeViolation("DOWNGRADE_OR_NOOP_BLOCKED")

        # Optional: block skipping major versions
        if target.major > current.major + 1:
            raise SchemaUpgradeViolation("MAJOR_VERSION_SKIP_BLOCKED")

        return True

    def apply_upgrade(self, manifest):

        self.validate_upgrade(manifest)

        # If no store provided → non-anchored mode (backward compatible)
        if self.evidence_store is None:
            self.current_version = manifest.to_version
            return None

        # Anchored governance mode
        record = build_governance_upgrade_record(
            manifest=manifest,
            store=self.evidence_store,
        )

        receipt = append_evidence_record(
            record,
            store=self.evidence_store,
        )

        if receipt is None:
            raise SchemaUpgradeViolation("UPGRADE_EVIDENCE_COMMIT_FAILED")

        self.current_version = manifest.to_version

        return receipt.merkle_root
