# RFC-MEIKA-TRACK-A-FREEZE

Title: Meika Track-A Freeze — Deterministic Security Kernel  
Status: **FROZEN (Immutable Law)**  
Applies To: Track-A marked code and tests  
Audience: Engineers, Security Architects, Auditors, Regulators  
Effective Date: At first green Track-A CI  

---

## 1. PURPOSE

This document formally freezes **Track A** of the Meika system.

Track A defines the **Security Kernel (LAW)** — the only component with authority
to decide whether execution is **ALLOWED or DENIED**.

After this freeze:
- Track-A semantics **MUST NOT CHANGE**
- All future work proceeds in Track-B / Track-C / Track-D
- Any violation of Track-A invariants is a **system defect**

---

## 2. SCOPE OF TRACK A

Track A is the **deterministic decision kernel**.

It is explicitly **not**:
- IAM
- Session management
- Policy engine
- Evidence store
- Observability system

Track A answers exactly one question:

> “Given a frozen security context, is execution allowed — yes or no?”

---

## 3. NON-NEGOTIABLE GUARANTEES

### 3.1 Determinism

Track A **MUST** be deterministic:
- Same input → same decision semantics
- No randomness
- No reliance on wall-clock time for logic
- No external I/O
- No hidden state

---

### 3.2 Context Immutability

- `SecurityContext` is frozen
- Device snapshots are immutable
- Grants never mutate context
- Policies never mutate context
- Any mutation attempt is invalid behavior

---

### 3.3 Deny by Default

Track A is deny-first:
- Missing context → DENY
- Unauthenticated → DENY
- Any invariant violation → DENY

There is **no implicit allow**.

---

### 3.4 Absolute Precedence Order

The enforcement order is fixed and immutable:

1. Context validity
2. Authentication
3. Device precedence (hard stops)
4. Device trust (hardware, attestation, binding)
5. Grant enforcement
6. Policy evaluation (advisory only)

Policy **can never override** earlier stages.

---

### 3.5 Grants Are Constraints

- Expired grant → DENY
- Intent mismatch → DENY
- Grants do not elevate privilege
- Grants cannot be repaired or overridden by policy

---

### 3.6 Policy Is Advisory Only

- Policy runs last
- Policy may recommend ALLOW or DENY
- Invalid policy output → DENY
- Policy-originated DENY **without evidence** → FORBIDDEN

---

### 3.7 DENY Must Be Evidenced

Every DENY **MUST** include:
- A canonical deny reason
- A deterministic context hash
- A timestamp

Kernel-level DENY is automatically evidenced.
Silent DENY is forbidden.

---

## 4. WHAT TRACK A MUST NEVER DO

Track A **MUST NOT**:
- Commit evidence
- Perform I/O
- Emit events
- Call databases
- Depend on observability
- Retry or “heal” failures
- Trust external services
- Mutate context
- Contain business logic

---

## 5. AUTHORITY BOUNDARY

| Component            | Authority Level |
|---------------------|-----------------|
| SecurityPipeline    | **LAW (Track A)** |
| SecureIDKernel      | Execution + Evidence (Track B) |
| Policy Engine       | Advisory only |
| Evidence Engine     | Memory only |
| Observability       | Non-authoritative |

Track A **cannot be bypassed**.

---

## 6. TEST ENFORCEMENT (MANDATORY)

Track A is enforced via pytest markers.

### 6.1 Track-A Law Test Set

```bash
pytest -m track_a
This test set MUST ALWAYS PASS.

If it fails:

The change is invalid

The commit must not be merged

6.2 Track Separation Proof
pytest -m "not track_a"


Track-B/C/D tests must never require Track-A changes.

7. ALLOWED CHANGES AFTER FREEZE

Only the following are permitted:

Comments

Documentation

Typing improvements

Additional tests that reinforce invariants

All must preserve semantics.

8. FORBIDDEN CHANGES AFTER FREEZE

The following require a new RFC and audit:

Changing precedence order

Changing deny reasons

Relaxing determinism

Allowing policy override

Allowing execution without evidence

Introducing side effects into Track A

9. FREEZE VERIFICATION CHECKLIST

Track A is frozen only if:

pytest -m track_a passes

Full test suite passes

Track-A files are marker-protected

Track-B code does not modify Track-A

Evidence determinism is not asserted at kernel level

10. DECLARATION

By freezing Track A, Meika guarantees:

Deterministic enforcement

No implicit trust

No hidden authority

Audit-proof denial semantics

This kernel defines the law of execution for the entire system.

All future capability builds on top of this law — never through it.
