RFC-MEIKA-TRACK-C-EVIDENCE-MEMORY

Status: Draft → Ready for Freeze
Track: C — Evidence Memory
Audience: Security architects, auditors, compliance teams, core maintainers
Depends on: Track A (Kernel), Track B (Evidence Engine)
Normative Language: MUST / MUST NOT / SHALL / SHOULD are binding

1. Purpose

This RFC defines the Evidence Memory Layer for the Meika Security Kernel.

Track C extends the hardened Evidence Engine (Track B) with long-term, tiered, auditable storage while preserving the following invariants:

Cryptographic immutability

Global chain continuity

Deterministic replay

Storage-agnostic design

Regulatory auditability

Evidence Memory is not an enforcement authority and must never influence security decisions.

2. Non-Goals

Track C explicitly does not:

Change decision semantics

Modify evidence hashes

Introduce mutable records

Perform policy enforcement

Replace the Track-B append engine

3. Core Design Principle

Evidence Memory is a capability, not a database.

The kernel and evidence engine interact only through interfaces, never concrete storage technologies.

4. Evidence Memory Architecture
┌────────────┐
│ Track A    │  (Decision Kernel)
└─────┬──────┘
      │
┌─────▼──────┐
│ Track B    │  (Evidence Engine)
│ Append-Only│
└─────┬──────┘
      │
┌─────▼─────────────────────────────┐
│ Track C — Evidence Memory           │
│ ┌──────────┐ ┌──────────┐ ┌─────┐ │
│ │ HOT      │ │ WARM     │ │COLD │ │
│ └──────────┘ └──────────┘ └─────┘ │
│        └────── Global Chain ──────┘
└────────────────────────────────────┘

5. Canonical Interfaces
5.1 EvidenceAppendStore (Authoritative Write Path)
class EvidenceAppendStore(Protocol):
    def append(self, record: EvidenceRecord) -> str
    def last_hash(self) -> Optional[str]
    def next_sequence(self) -> int


Invariants:

MUST be append-only

MUST fail closed

MUST enforce strict chain ordering

MUST enforce monotonic sequence numbers

Only Track-B components may invoke this interface.

5.2 EvidenceReadStore (Audit / Replay)
class EvidenceReadStore(Protocol):
    def get(self, record_hash: str) -> EvidenceRecord
    def range(self, start_seq: int, end_seq: int) -> list[EvidenceRecord]
    def verify_chain(self) -> bool


Invariants:

MUST be read-only

MUST support deterministic ordering

MUST allow offline verification

MUST NOT require write access to verify integrity

5.3 EvidenceRetentionController (Non-Authoritative)
class EvidenceRetentionController(Protocol):
    def get_state(self, record_hash: str) -> RetentionState
    def transition(self, record_hash: str, target: RetentionState) -> None


Rules:

MUST NOT mutate evidence

MUST NOT rewrite hashes

MUST NOT affect kernel behavior

Controls placement, not existence

6. Tiered Memory Model

Track C defines logical tiers, not physical storage.

Tier	Purpose	Mutability
HOT	Recent evidence	Immutable
WARM	Indexed audit	Immutable
COLD	Long-term archive	Immutable
FROZEN	Legal hold / WORM	Immutable

All tiers:

Share a single global chain

Preserve sequence continuity

Support verification

7. Chain Continuity Guarantees
7.1 Global Chain

Evidence records form a single, global, linear chain:

GENESIS → R1 → R2 → R3 → … → Rn


Movement across tiers MUST NOT:

Break sequence numbers

Reset previous_hash

Fork chains

Re-hash records

7.2 Cross-Tier Verification

Auditors MUST be able to verify:

No missing sequence numbers

No hash mismatches

No unauthorized truncation

Even if records are offline, proof of absence must be detectable.

8. Replay Semantics

Track C guarantees:

Full replay from GENESIS

Partial replay by sequence range

Deterministic reconstruction

Offline replay capability

Replay MUST NOT depend on:

runtime state

external clocks

mutable metadata

9. Failure Semantics
Scenario	Required Behavior
Storage outage	Kernel unaffected
Cold tier unavailable	WARN only
Retention misconfig	Detectable via audit
Corrupt record	Verification fails
Missing range	Audit MUST fail

No silent degradation is permitted.

10. Security Invariants

The following MUST always hold:

Evidence hashes never change

Sequence numbers never reset

No tier may introduce forks

Read paths cannot mutate state

Retention cannot suppress detection

Kernel never blocks on memory reads

11. Compliance Alignment

Track C enables:

SOC 2 Type II auditability

ISO 27001 evidence retention

NIST SP 800-53 AU / IR controls

Legal defensibility of logs

Evidence Memory is designed to outlive storage technologies.

12. Future Compatibility

This design explicitly supports:

Post-quantum hash upgrades (via versioned payloads)

Cross-region replication

External notarization

Zero-trust audit consumers

No interface changes are required.

13. Freeze Criteria

Track C may be frozen when:

Interfaces are finalized

Tier rules are documented

Replay guarantees are validated

Failure semantics are tested

After freeze:

Interfaces MUST NOT change

Only implementations may evolve
