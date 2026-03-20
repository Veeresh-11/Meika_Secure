import pytest
from app.security.schema.upgrade_engine import UpgradeEngine
from app.security.schema.manifest import MigrationManifest
from app.security.schema.exceptions import SchemaUpgradeViolation


def test_valid_upgrade():
    engine = UpgradeEngine("1.0.0")

    manifest = MigrationManifest(
        migration_id="m1",
        from_version="1.0.0",
        to_version="1.1.0",
        migration_hash="abc",
        signed_by="governance",
    )

    engine.apply_upgrade(manifest)

    assert engine.current_version == "1.1.0"


def test_downgrade_blocked():
    engine = UpgradeEngine("1.1.0")

    manifest = MigrationManifest(
        migration_id="m2",
        from_version="1.1.0",
        to_version="1.0.0",
        migration_hash="abc",
        signed_by="governance",
    )

    with pytest.raises(SchemaUpgradeViolation):
        engine.apply_upgrade(manifest)


def test_invalid_from_version_blocked():
    engine = UpgradeEngine("1.0.0")

    manifest = MigrationManifest(
        migration_id="m3",
        from_version="0.9.0",
        to_version="1.1.0",
        migration_hash="abc",
        signed_by="governance",
    )

    with pytest.raises(SchemaUpgradeViolation):
        engine.apply_upgrade(manifest)
