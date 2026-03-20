"""
TRACK D — Error Envelope Schema

This schema defines the canonical, externally visible
error envelope for all Track-D interfaces.

Errors are:
- Deterministic
- Replay-traceable
- Version-stable
- Auditor-safe

This schema is LAW.
Any change requires a new RFC.
"""

error_envelope_schema = {
    "type": "object",
    "required": [
        "error_code",
        "error_class",
        "human_message",
    ],
    "additionalProperties": False,
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
            "required": ["record_hash"],
            "additionalProperties": False,
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
