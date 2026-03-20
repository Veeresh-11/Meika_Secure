# Evidence & Audit Model

## Evidence Contents
- Identity ID
- Policy ID + version
- Decision
- Risk score
- Device context
- Timestamp

## Properties
- Append-only
- Tamper-evident hashing
- No admin deletion
- Read-only forensic access

## Purpose
- Regulatory compliance
- Incident reconstruction
- Trust verification

## Device Posture Evidence

The system captures immutable evidence for all device posture evaluations.

Evidence includes:
- Signal name and value
- Verification result
- Signal freshness
- Policy impact
- Human-readable explanation

Evidence is recorded:
- Before sensitive access
- During elevated access
- After access completion

Missing or unverifiable posture signals are treated as restrictive and are always auditable.
## Investigation Access Evidence

Investigation access produces the highest-fidelity audit evidence.

All investigative queries are:
- Individually logged
- Correlated to an incident
- Bound to device identity
- Human-explainable

Investigation access is read-only by default.
Mutation requires separate JIT admin elevation.
