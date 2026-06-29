import pytest
from app.security.schema.upgrade_engine import UpgradeEngine
from app.security.schema.manifest import MigrationManifest
from app.security.evidence.store import InMemoryEvidenceStore
from app.security.recovery import verify_store_integrity


def test_upgrade_is_anchored():

    store = InMemoryEvidenceStore()
    engine = UpgradeEngine("1.0.0", store)

    manifest = MigrationManifest(
        migration_id="m1",
        from_version="1.0.0",
        to_version="1.1.0",
        migration_hash="abc",
        signed_by="governance",
    )

    root = engine.apply_upgrade(manifest)

    assert root is not None
    assert engine.current_version == "1.1.0"

    # Evidence chain must remain valid
    assert verify_store_integrity(store)
    
def test_apply_upgrade_commit_failure():
    from unittest.mock import patch
    from app.security.schema.upgrade_engine import UpgradeEngine
    from app.security.schema.manifest import MigrationManifest
    from app.security.schema.exceptions import SchemaUpgradeViolation

    manifest = MigrationManifest(
        migration_id="m1",
        from_version="1.0.0",
        to_version="1.1.0",
        migration_hash="abc",
        signed_by="root",
    )

    engine = UpgradeEngine(
        current_version="1.0.0",
        evidence_store=object(),
    )

    with patch(
        "app.security.schema.upgrade_engine.build_governance_upgrade_record"
    ) as build_mock, patch(
        "app.security.schema.upgrade_engine.append_evidence_record",
        return_value=None,
    ):
        build_mock.return_value = object()

        with pytest.raises(
            SchemaUpgradeViolation,
            match="UPGRADE_EVIDENCE_COMMIT_FAILED",
        ):
            engine.apply_upgrade(manifest)
