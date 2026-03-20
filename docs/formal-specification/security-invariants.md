# Formal Security Invariants

## Purpose

This document defines invariants that MUST hold
for Meika Authenticator to be considered secure.

An invariant is a condition that must be true
in all executions, under all failures.

---

## Invariant I1 — Explicit Intent

Every access decision MUST be associated with
an explicit, declared intent.

Formal:
∀ request r: execute(r) ⇒ intent(r) ∈ AllowedIntents

---

## Invariant I2 — Grant-Bound Privilege

Privileged actions MUST have a valid, active grant.

Formal:
∀ action a: privileged(a) ⇒ ∃ grant g:
  g.intent = a.intent ∧
  now < g.expires_at ∧
  ¬revoked(g)

---

## Invariant I3 — No Standing Privilege

No user or device possesses persistent privilege.

Formal:
¬∃ principal p: privilege(p) without time-bound grant

---

## Invariant I4 — Evidence Precedence

Privileged execution MUST NOT occur
unless evidence is successfully written.

Formal:
execute(a) ⇒ evidence_written(pre, a)

---

## Invariant I5 — Containment Dominance

Containment overrides all grants and decisions.

Formal:
containment_active(p) ⇒ ¬execute(a) for all a by p

---

## Invariant I6 — Fail-Closed Recovery

After failure or restart, no trust is restored implicitly.

Formal:
restart ⇒ ∀ grants g: g.invalid

---

## Invariant I7 — Restrictive Risk

Risk signals may restrict but never grant access.

Formal:
risk(r) ⇒ decision ∈ {deny, restrict}
