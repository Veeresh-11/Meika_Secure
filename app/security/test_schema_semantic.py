import pytest
from app.security.schema.upgrade_engine import UpgradeEngine
from app.security.schema.manifest import MigrationManifest
from app.security.schema.exceptions import SchemaUpgradeViolation


def test_semantic_ordering_correct():
    engine = UpgradeEngine("1.2.0")

    manifest = MigrationManifest(
        migration_id="m1",
        from_version="1.2.0",
        to_version="1.10.0",
        migration_hash="abc",
        signed_by="gov",
    )

    engine.apply_upgrade(manifest)

    assert engine.current_version == "1.10.0"


def test_major_skip_blocked():
    engine = UpgradeEngine("1.0.0")

    manifest = MigrationManifest(
        migration_id="m2",
        from_version="1.0.0",
        to_version="3.0.0",
        migration_hash="abc",
        signed_by="gov",
    )

    with pytest.raises(SchemaUpgradeViolation):
        engine.apply_upgrade(manifest)


def test_invalid_version_format():
    engine = UpgradeEngine("1.0.0")

    manifest = MigrationManifest(
        migration_id="m3",
        from_version="1.0.0",
        to_version="invalid",
        migration_hash="abc",
        signed_by="gov",
    )

    with pytest.raises(ValueError):
        engine.apply_upgrade(manifest)
