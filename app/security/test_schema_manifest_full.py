# app/security/test_schema_manifest_full.py

import hashlib

from app.security.schema.manifest import MigrationManifest


def test_manifest_fingerprint():
    manifest = MigrationManifest(
        migration_id="m1",
        from_version="1",
        to_version="2",
        migration_hash="abc123",
        signed_by="meika",
    )

    canonical = "m1|1|2|abc123|meika"

    expected = hashlib.sha256(
        canonical.encode()
    ).hexdigest()

    assert manifest.fingerprint() == expected