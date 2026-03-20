"""
TRACK D — SOC2 Export Manifest Schema
"""

soc2_export_manifest_schema = {
    "type": "object",
    "required": [
        "export_type",
        "period_start",
        "period_end",
        "generated_at",
        "kernel_version",
        "hash_algorithm",
        "bundle_hash",
    ],
    "additionalProperties": False,
    "properties": {
        "export_type": {
            "type": "string",
            "enum": ["SOC2_TYPE_II"],
        },
        "period_start": {"type": "string"},
        "period_end": {"type": "string"},
        "generated_at": {"type": "string"},
        "kernel_version": {"type": "string"},
        "hash_algorithm": {"type": "string"},
        "bundle_hash": {"type": "string"},
        "records": {"type": "array"},
        "controls": {"type": "object"},
        "signature": {"type": "string"},
        "signing_algorithm": {"type": "string"},
        "key_id": {"type": "string"},
        "notes": {"type": "string"},
    },
}
