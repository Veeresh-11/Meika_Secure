# RFC-MEIKA-EVIDENCE-ENGINE-HARDENING

Title: Evidence Engine Hardening — Append-Only & Merkle Proof  
Status: ACTIVE  
Track: B (Kernel Enforcement)  
Depends On:
- RFC-MEIKA-TRACK-A-FREEZE
- RFC-MEIKA-TRACK-B-KERNEL-AUTHORITY  

Audience: Engineers, Security Architects, Auditors

---

## 1. PURPOSE

This RFC hardens the Meika Evidence Engine.

It defines **cryptographic and structural guarantees** that make
execution decisions permanently provable and tamper-evident.

This document upgrades evidence from *logging* to *proof*.

---

## 2. NON-NEGOTIABLE INVARIANTS

The evidence engine MUST guarantee:

1. Append-only semantics
2. Deterministic record serialization
3. Cryptographic chaining
4. Ordering sensitivity
5. Fail-closed behavior
6. No overwrite or delete capability

Violation of any invariant is a **system defect**.

---

## 3. EVIDENCE RECORD MODEL

Each evidence record MUST contain:

- `sequence_number` (monotonic)
- `timestamp`
- `decision_digest`
- `context_hash`
- `previous_hash`
- `payload_hash`
- `record_hash`

All hashes MUST be SHA-256 or stronger.

---

## 4. MERKLE CHAINING MODEL

### 4.1 Linear Merkle Chain (Mandatory Baseline)

Each record hash is computed as:

record_hash = H(
sequence_number ||
previous_hash ||
payload_hash
)


Where:
- `previous_hash` = last committed record hash
- Genesis record has a fixed zero-hash

---

### 4.2 Root Hash

The Merkle root at time N is:



root_N = record_hash_N


Reordering ANY record changes the root.

Deletion breaks the chain.

---

## 5. APPEND-ONLY GUARANTEE

Evidence stores MUST:

- Expose ONLY `append(record)`
- Never expose update
- Never expose delete
- Never expose replace

Any implementation exposing mutation is **invalid**.

---

## 6. FAIL-CLOSED SEMANTICS

If any of the following occur:

- Hash computation fails
- Store append fails
- Sequence mismatch
- Previous hash mismatch

Then:

- Evidence commit FAILS
- Kernel MUST deny execution
- No retries inside kernel
- No silent fallback

---

## 7. DETERMINISM BOUNDARY

- Evidence hashes are NOT required to be deterministic across runs
- Evidence determinism is scoped to **within a single chain**
- Track-A determinism MUST remain unaffected

---

## 8. AUDITABILITY

An auditor MUST be able to:

- Recompute the full chain
- Detect missing records
- Detect reordering
- Detect deletion
- Verify kernel enforcement occurred

No trust in runtime systems is assumed.

---

## 9. TEST REQUIREMENTS (MANDATORY)

The following test classes MUST exist and pass:

- Append-only enforcement
- Chain integrity
- Reordering detection
- Partial commit failure
- Kernel fail-closed behavior

These tests are **Track-B law** once merged.

---

## 10. FORBIDDEN BEHAVIOR

The evidence engine MUST NOT:

- Repair chains silently
- Skip records
- Allow partial writes
- Mask store failures
- Depend on clocks for ordering

---

## 11. DECLARATION

After this RFC:

> “If execution occurred, proof exists — or execution did not happen.”

Evidence is not observability.
Evidence is authority memory.

Track A decides.
Track B proves.
