from jsonschema import validate, ValidationError
from datetime import datetime

from app.security.track_d.schemas import soc2_export_manifest_schema


def test_soc2_export_manifest_schema_valid():
    """
    Schema-level test only.

    This test verifies that a minimal, well-formed SOC2
    export manifest is accepted by the schema.

    It does NOT test export logic.
    """

    payload = {
        "export_type": "SOC2_TYPE_II",
        "period_start": "2026-01-01T00:00:00Z",
        "period_end": "2026-03-31T23:59:59Z",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "kernel_version": "1.0.0",
        "hash_algorithm": "SHA-256",
        "bundle_hash": "c" * 64,
    }

    validate(instance=payload, schema=soc2_export_manifest_schema)


def test_soc2_export_rejects_missing_required_fields():
    """
    Schema must reject payloads missing required fields.
    """

    payload = {
        "export_type": "SOC2_TYPE_II",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        # missing period_start, period_end, kernel_version, hash_algorithm, bundle_hash
    }

    try:
        validate(instance=payload, schema=soc2_export_manifest_schema)
        assert False, "Schema should reject missing required fields"
    except ValidationError:
        assert True
