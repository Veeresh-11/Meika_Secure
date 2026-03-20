🧊 MEIKA — SPRINT-A FREEZE DOCUMENT

Track-A: Deterministic Security Decision Kernel

Status: FROZEN
Authority Level: CONSTITUTIONAL (may only change if a security invariant is proven wrong)
Audience: Core engineers, security architects, auditors, regulators
Last Verified: pytest app/security → 47 / 47 PASS

1️⃣ PURPOSE OF SPRINT-A

Sprint-A defines the authoritative security decision law of Meika.

It answers exactly one question:

Given a frozen security context, should this intent be allowed or denied — and why?

Sprint-A does not execute actions, write evidence, emit logs, or integrate with APIs.
It is intentionally pure, deterministic, and side-effect free.

All higher tracks (policy, evidence, observability, MIS, APIs) are subordinate to this law.

2️⃣ WHAT SPRINT-A IS (AND IS NOT)
✅ Sprint-A IS

A deterministic decision kernel

The only authority that can decide ALLOW or DENY

Enforcer of:

context validity

device precedence

grant constraints

policy safety

Producer of explainable DENY decisions

❌ Sprint-A IS NOT

An IAM system

A policy engine

An evidence store

An observability system

A session manager

A runtime execution engine

If something is not enforced here, it has no authority anywhere else.

3️⃣ AUTHORITATIVE FILE SET (FROZEN)

The following files collectively define Track-A law.
They MUST be treated as a unit.

Core Data Models

app/security/context.py
Why: Defines the immutable input boundary
Invariant: Context is frozen; mutation is forbidden

app/security/decision.py
Why: Defines the only valid decision representation
Invariant: No implicit ALLOW, no hidden fields

app/security/results.py
Why: Canonical deny reasons and advisory result types
Invariant: Reasons are enumerable and auditable

Enforcement & Errors

app/security/errors.py
Why: Separates recoverable DENY from invariant violations
Invariant:

SecurityPipelineError → expected DENY

SecurityInvariantViolation → system fault

Device Law (Absolute)

app/security/device_snapshot.py
Why: Immutable device posture boundary
Invariant: No live device objects, no TOCTOU

app/security/precedence.py
Why: Defines absolute device ordering
Invariant: First failure wins, policy never runs after hard-stop

app/security/device_trust.py
Why: Maps device posture → canonical DenyReason
Invariant: No policy override, no soft failure

Decision Kernel

app/security/pipeline.py
Why: Implements Track-A decision flow
Invariant:

No side effects

DENY always evidenced

Deterministic semantics

⚠️ Only the SecurityPipeline portion is Track-A.
SecureIDKernel is a Track-B edge wrapper and must not weaken Track-A guarantees.

4️⃣ DECISION ORDER (NON-NEGOTIABLE)

Sprint-A enforces the following fixed order:

Context validity

Missing context → DENY

Unauthenticated → DENY

Device precedence (absolute)

clone_confirmed

not registered

revoked / lost

compromised

hardware / attestation / binding failures

Grant enforcement

expired → DENY

intent mismatch → DENY

Policy evaluation (advisory only)

may recommend

may deny

may not override anything above

DENY auto-evidence

every DENY is explainable

context hash is deterministic

There are no other legal paths.

5️⃣ DETERMINISM CONTRACT

Sprint-A guarantees:

Same input → same outcome

Same input → same reason

Same input → same context hash

Sprint-A does not guarantee:

Evidence hash determinism
(that is a Track-B concern by design)

Time may appear in metadata, but never affects logic.

6️⃣ TEST VERIFICATION (MANDATORY)

Sprint-A is frozen only because tests prove it.

Verification command:

pytest app/security


Expected result:

47 passed


If this ever fails, Sprint-A is no longer valid.

7️⃣ EXPLICIT NON-ISSUES (DO NOT “FIX”)

The following behaviors are intentional:

Policy DENY without evidence → forbidden

Kernel may raise invariant violations

ALLOW without evidence → forbidden

Evidence hash non-determinism → acceptable

No implicit ALLOW anywhere

8️⃣ CHANGE RULES AFTER FREEZE

After this freeze:

❌ You may NOT modify Track-A files casually

❌ You may NOT “simplify” precedence

❌ You may NOT relax grant or device enforcement

You may:

Add Track-B, C, D features around the kernel

Add tests that further constrain behavior

Fix Track-A code only if a test proves an invariant violation

✅ FINAL DECLARATION

Sprint-A is complete.

The Meika security kernel is now:

Deterministic

Auditable

Precedence-safe

Policy-resilient

Regulator-explainable

All future work must respect this law.
