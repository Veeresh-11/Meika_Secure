# RFC-MEIKA-TRACK-B-KERNEL-AUTHORITY

Title: Meika Track-B — Kernel Authority & Evidence Enforcement  
Status: ACTIVE  
Depends On: RFC-MEIKA-TRACK-A-FREEZE  
Audience: Engineers, Security Architects, Auditors  

---

## 1. PURPOSE

This RFC defines **Track B** of the Meika system.

Track B is responsible for **executing Track-A decisions** and
**making them permanently provable** through evidence.

Track B **has no authority to decide**.
It only enforces and records decisions produced by Track A.

---

## 2. AUTHORITY MODEL

Track B **inherits authority** strictly from Track A.

- Track A decides
- Track B enforces
- Track C remembers
- Track D transports

If Track B fails, execution **must fail closed**.

---

## 3. SECUREIDKERNEL ROLE

`SecureIDKernel` is the Track-B execution boundary.

Responsibilities:
- Call Track-A evaluation
- Require evidence commit for ALLOW
- Attach evidence hash to decisions
- Fail closed on commit failure
- Guard observability side effects

---

## 4. EVIDENCE ENFORCEMENT RULES

### 4.1 Evidence Is Mandatory

- ALLOW **requires** successful evidence commit
- DENY must already be evidenced by Track A
- Missing evidence → invariant violation

---

### 4.2 Append-Only Guarantee

Evidence stores:
- MUST be append-only
- MUST not allow deletion
- MUST not allow overwrite
- MUST preserve ordering

---

### 4.3 Commit Failure Semantics

If evidence cannot be committed:
- Execution MUST NOT proceed
- Kernel MUST raise invariant violation
- No retries inside kernel
- No fallback paths

Fail-closed is mandatory.

---

## 5. DETERMINISM BOUNDARY

Track B **does not require determinism** for:
- Evidence hashes
- Merkle roots
- Storage order

Track B **must not affect Track-A determinism**.

---

## 6. OBSERVABILITY IS NON-AUTHORITATIVE

Observability systems:
- Receive best-effort events
- Must never affect enforcement
- Must never raise exceptions outward

Failure to emit logs is ignored.

---

## 7. TEST ENFORCEMENT

Track B is enforced via pytest markers.

```bash
pytest -m kernel
pytest -m evidence
Track-B tests:

May fail independently of Track A

Must never force Track-A changes

8. FORBIDDEN BEHAVIOR

Track B MUST NOT:

Modify Track-A logic

Mutate SecurityContext

Introduce implicit allow

Recover from evidence failure

Retry commits silently

9. SECURITY MODEL

Track B assumes:

Storage may fail

Observability may fail

Policy may misbehave

Track B trusts only Track A decisions.

10. DECLARATION

Track B exists to ensure that:

“If execution happened, proof exists forever.”

No execution without evidence.
No evidence without authority.

Track A decides.
Track B enforces.

This boundary is absolute.
