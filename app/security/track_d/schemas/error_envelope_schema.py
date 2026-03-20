"""
TRACK D — Error Envelope Schema
"""

error_envelope_schema = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "error_code",
        "error_class",
        "human_message",
    ],
    "properties": {
        "error_code": {
            "type": "string",
            "pattern": "^MEIKA_[A-Z0-9_]+$",
        },
        "error_class": {
            "type": "string",
            "enum": [
                "CONTEXT",
                "AUTH",
                "DEVICE",
                "GRANT",
                "POLICY",
                "EVIDENCE",
                "REPLAY",
                "STORAGE",
                "EXPORT",
                "INFRA",
            ],
        },
        "human_message": {
            "type": "string",
        },
        "kernel_version": {
            "type": "string",
        },
        "fingerprint": {
            "type": "string",
        },
        "evidence_ref": {
            "type": "object",
            "additionalProperties": False,
            "required": ["record_hash"],
            "properties": {
                "record_hash": {"type": "string"},
                "sequence": {"type": "integer"},
            },
        },
        "authoritative": {
            "type": "boolean",
        },
    },
}
