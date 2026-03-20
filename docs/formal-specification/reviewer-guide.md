# Formal Review Guide

## Purpose

Enable independent reviewers to verify
Meika’s security properties.

---

## Reviewer Steps

1. Inspect invariants
2. Inspect enforcement code
3. Run test suites
4. Inspect evidence schemas
5. Validate fail-closed behavior

---

## Reviewer Guarantees

Reviewers should be able to conclude:
- No implicit trust exists
- No bypass paths exist
- No privilege persists
- Failures reduce power

No proprietary tools are required.
