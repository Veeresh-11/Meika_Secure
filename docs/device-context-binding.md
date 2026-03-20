# Meika Authenticator — Device & Context Binding

## Purpose

This document defines how Meika binds identity authentication to device posture and contextual signals to enforce Zero-Trust access control.

No identity is considered fully trusted without valid device and context binding.

---

## Core Principles

1. Identity alone is insufficient for access
2. Device trust expires automatically
3. Context can restrict but never grant access
4. All bindings are evaluated per request
5. Binding failures result in progressive restriction

---

## Device Trust Model

A device represents a cryptographically verifiable execution environment.

### Device Attributes

- device_id
- hardware_backed
- attestation_level
- trust_state
- trust_expiry

### Device Trust Rules

- Device trust is time-bound
- Device trust is identity-bound
- Device trust is revocable
- Device changes require step-up authentication

---

## Context Signals

Context signals are evaluated continuously and independently.

Examples include:

- Location consistency
- Time window validity
- Network reputation
- Behavioral deviation
- Device velocity anomalies

---

## Context Constraints

- Context MUST NOT grant access
- Context MAY:
  - Require step-up authentication
  - Reduce session TTL
  - Narrow permissions
- Context influence MUST decay over time

---

## Binding Evaluation

Device and context binding is evaluated:

- At authentication
- On sensitive actions
- Periodically during session lifetime

Failure in binding evaluation results in:

1. Step-up authentication
2. Scope reduction
3. Session isolation
4. Access denial (last resort)

---

## Audit & Evidence

All binding decisions MUST emit:

- Device state
- Context summary
- Policy reference
- Resulting action

This evidence MUST be retained for audit and investigation.

---

## Final Assertion

Meika enforces Zero-Trust by continuously validating identity, device, and context rather than relying on static sessions or network location.
