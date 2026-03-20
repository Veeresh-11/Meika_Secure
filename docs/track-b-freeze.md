RFC-MEIKA — Track-B Freeze

Evidence Engine & Shadow / Simulation Mode

Status: 🔒 FROZEN
Supersedes: Track-B drafts
Depends on: Track-A (Frozen)
Date: (fill in)

1. Purpose

Track-B extends the deterministic kernel (Track-A) with cryptographically verifiable, append-only evidence enforcement, and introduces safe Simulation / Shadow Mode for rollout and experimentation.

This track ensures that no ALLOW decision can exist without durable proof, while preserving strict fail-closed semantics.

2. Scope (What Track-B Owns)

Track-B is responsible for:

Evidence record construction

Hash chaining & ordering

Append-only enforcement

Evidence commit receipts

Kernel ↔ evidence boundary

Shadow / Simulation evaluation (non-authoritative)

Track-B does not handle long-term storage or retention.

3. Normative Guarantees
🔐 Evidence Invariants

Evidence is append-only

No delete or overwrite APIs exist

Each record cryptographically binds:

sequence number

previous hash

payload hash

Chain breaks fail closed

Reordering produces different hashes

Identical input → deterministic hash

⚖️ Enforcement Invariants

ALLOW without evidence commit is forbidden

Evidence commit failure → DENY

Kernel decisions are authoritative

Observability is non-authoritative

🧪 Simulation / Shadow Mode

Runs strictly after enforcement

Cannot modify decision outcome

Cannot write evidence

Exceptions are swallowed

Safe for production rollout

4. Test Coverage

All Track-B guarantees are enforced by tests:

Append-only behavior

Atomic commit semantics

Chain integrity

Hash determinism

Reordering detection

Kernel + evidence integration

Simulation safety & isolation

Result:
✅ All Track-B tests passing
✅ Track-A + Track-B + Simulation validated together

5. Explicit Non-Goals

The following are out of scope for Track-B:

Evidence retention policy

Hot / cold storage tiers

Archival & compaction

External audit APIs

Multi-node consensus

Cross-region replication

These are deferred to Track-C.

6. Freeze Declaration

Track-B is hereby frozen.
No backward-incompatible changes are permitted.

Any extension must be introduced under a new track.

Core Track-B Files
🔹 app/security/pipeline.py

Role: Kernel ↔ Evidence boundary

Enforces:

ALLOW ⇒ evidence commit

Fail-closed semantics

Hosts Simulation / Shadow execution

Ensures observability is non-authoritative

✔ Authoritative
✔ Security-critical
✔ Frozen after Track-B

🔹 app/security/evidence/models.py

Role: Evidence record schema

Defines EvidenceRecord

Self-verifying structure

No store dependency

Immutable, hash-complete

✔ Pure data model
✔ Safe to export externally

🔹 app/security/evidence/engine.py

Role: Canonical evidence construction

Deterministic payload hashing

Record hash chaining

Evidence receipt generation

No side effects during build

✔ Single source of truth
✔ All evidence must flow through here

🔹 app/security/evidence/store.py

Role: Append-only enforcement

Enforces:

no overwrite

no delete

strict chaining

monotonic sequencing

In-memory implementation for now

✔ Enforcement layer
✔ Replaceable in Track-C

🔹 app/security/evidence/writer.py

Role: Compatibility / legacy bridge

Wraps engine + store

Used by:

legacy paths

isolated tests

⚠️ Not authoritative
⚠️ May be deprecated in Track-C
