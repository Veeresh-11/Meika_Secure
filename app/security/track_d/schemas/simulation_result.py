"""
TRACK D — Simulation Result Schema

This schema defines the non-authoritative output of
Track-D Simulation / Shadow Mode evaluation.

Simulation results:
- MUST NOT be authoritative
- MUST NOT deny access
- MUST NOT emit evidence
- MUST be explicitly labeled as non-authoritative

This schema is LAW.
Any change requires a new RFC.
"""

simulation_result_schema = {
    "type": "object",
    "required": [
        "simulated_outcome",
        "authoritative",
    ],
    "additionalProperties": False,
    "properties": {
        "simulated_outcome": {
            "type": "string",
            "enum": ["ALLOW", "DENY", "WARN"],
        },
        "authoritative": {
            "type": "boolean",
            "enum": [False],
        },
        "kernel_version": {
            "type": "string",
        },
        "simulated_reason": {
            "type": "string",
        },
        "warnings": {
            "type": "object",
        },
    },
}
