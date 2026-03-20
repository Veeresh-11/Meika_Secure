"""
TRACK D — Replay Verification Result Schema

Defines the authoritative output of replay verification.

This result MUST be:
- Deterministic
- Minimal
- Offline-verifiable
- Independent of runtime kernel state

This schema is LAW.
"""

replay_verification_result_schema = {
    "type": "object",
    "required": [
        "valid",
        "status",
    ],
    "additionalProperties": False,
    "properties": {
        "valid": {
            "type": "boolean",
            "description": "Whether the provided evidence chain is valid",
        },
        "status": {
            "type": "string",
            "description": "Deterministic replay verification status",
            "enum": [
                "CHAIN_VALID",
                "CHAIN_BROKEN",
                "HASH_MISMATCH",
                "ORDER_VIOLATION",
                "ALGORITHM_UNSUPPORTED",
                "INVALID_INPUT",
            ],
        },
        "details": {
            "type": "object",
            "description": "Optional non-authoritative diagnostic details",
            "additionalProperties": True,
        },
        "genesis_hash": {
            "type": "string",
            "description": "Optional genesis hash of the chain",
        },
    },
}
