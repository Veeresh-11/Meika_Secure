# Formal Specification Overview

## Purpose

This document defines the scope and intent of formal specification
within Meika Authenticator.

Formal specification is used to:
- Precisely state security guarantees
- Identify invariant properties
- Prevent ambiguous interpretations
- Enable independent verification

This specification complements (not replaces):
- Code
- Tests
- Policies
- Evidence

---

## What Is Formally Specified

The following properties are specified formally:

- Authorization invariants
- Grant lifecycle constraints
- Containment dominance
- Fail-closed behavior
- Recovery safety

---

## What Is NOT Formally Specified

- Cryptographic algorithm correctness
- External IdP correctness
- OS / hardware trust

These are treated as assumptions with bounded risk.

---

## Philosophy

If a property cannot be stated clearly,
it cannot be relied upon for security.
