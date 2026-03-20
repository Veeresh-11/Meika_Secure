Reference Kernel Alignment
(Normative Companion to RFC-MEIKA-DOC-DES&CRE-001)

Status: Final
Scope: Mandatory for all Meika kernel implementations
Location:

docs/formal-specification/reference-kernel-alignment.md

1. Purpose of This Document

The RFC defines what must be true.
This document defines how an implementation proves it is true.

Without this layer, the RFC is philosophy.
With this layer, the RFC becomes enforceable law.

This document exists to eliminate three historical failure modes in security systems:

Interpretation Drift – different engineers reading the same rule differently.

Partial Compliance – systems that claim adherence but violate edge cases.

Silent Regression – future changes that weaken guarantees without detection.

Any kernel claiming to be “Meika-compliant” MUST be auditable against this document.

2. Alignment Model: How Law Maps to Code

The Meika kernel is not a monolith. It is a deterministic pipeline composed of tightly constrained stages. Each stage corresponds directly to RFC invariants.

The alignment rule is simple but unforgiving:

Every externally observable behavior of the kernel must be traceable to an RFC clause, and every RFC clause must be enforceable by code and test.

This document therefore describes alignment along three axes:

Structural alignment (where the rule lives in code),

Behavioral alignment (what must happen at runtime),

Test alignment (how violation is detected).

3. Execution Ontology Alignment (RFC Section 0)

The RFC defines execution as any irreversible or externally observable action.
The kernel must reflect this definition not as commentary, but as control flow.

In implementation terms, this means that:

Execution-capable operations (I/O, signing, state mutation, token issuance) MUST be reachable only through a single, explicit execution gate.

Preparatory computation (policy evaluation, snapshot construction, risk scoring) MUST be structurally incapable of producing side effects.

In your current tree, this boundary is enforced by the pipeline orchestration layer. Any code path that can cause execution MUST require an execution permit produced by the kernel itself. There must be no “helper” methods, background threads, or callbacks that bypass this gate.

If a developer can accidentally trigger execution while “just computing something,” the implementation is non-compliant.

4. Decision Lifecycle Alignment (RFC Track A)

The RFC states that the kernel alone defines the decision lifecycle.
This means the lifecycle must be closed and explicit.

Alignment requires that:

A decision object cannot exist in a partially evaluated state.

Every decision must resolve to exactly one of: ALLOW or DENY.

There must be no implicit success paths, default allows, or exception-based bypasses.

In implementation terms, decision construction must be total.
If any required input (snapshot, time proof, device posture, grant state) is missing or malformed, the kernel must not “continue anyway.” It must terminate evaluation and emit a deny outcome with a typed reason.

Tests asserting “decision determinism” and “no magic strings” exist precisely to catch violations of this alignment.

5. Snapshot Boundary Alignment (RFC A2)

Snapshots exist to eliminate time-of-check/time-of-use attacks.
Alignment here is both structural and temporal.

Structurally:

Snapshots must be immutable objects.

No live references to mutable system state may leak into evaluation logic.

Temporally:

Every snapshot must carry a timestamp derived from a monotonic time source.

The kernel must validate snapshot freshness before allowing evaluation to continue.

If a snapshot is stale, the decision MUST fail closed.
If time integrity cannot be proven, the kernel MUST halt.

This ensures that the kernel never reasons about a world that no longer exists.

6. Precedence Alignment (RFC A3)

Precedence rules define reality ordering.
They are not policy preferences; they are physical constraints.

Alignment requires that:

Hardware and time checks execute before any policy logic.

Grant validity and revocation are evaluated before policy advice.

Policy evaluation can only refine a decision, never override higher-precedence facts.

In code, this means the evaluation order is fixed and unconfigurable.
No configuration file, feature flag, or runtime parameter may alter precedence.

If a policy can “skip” a device failure or time violation, the kernel is broken.

7. Evidence Enforcement Alignment (RFC A5 + A7)

This is the most critical alignment in the entire system.

The RFC states that execution is permitted only after evidence is committed.
Alignment demands hard atomicity, not “best effort.”

Concretely:

The kernel must construct the evidence record before execution.

Evidence must be committed to the Merkle-aggregated store.

The commit operation must return a cryptographic receipt.

Execution must require possession of that receipt.

If evidence commit fails, execution MUST be impossible.

This must be enforced structurally.
The execution path must be unreachable without the receipt object.

If execution can occur and evidence fails later, the implementation is non-compliant, regardless of intent.

8. Failure Classification Alignment (RFC Global Invariants)

Failures are facts, not events.

Alignment requires that:

Every failure mode maps to a known failure class (hardware, time, storage, attestation, policy VM).

Each failure produces a typed deny reason.

Failures are not retried, masked, or auto-recovered at runtime.

This ensures that instability cannot be exploited as a bypass mechanism.

A kernel that “tries again” after a failure is not resilient — it is attackable.

9. Time & HALT Alignment (RFC Time Integrity)

Time is a trust boundary.

Alignment requires that:

The kernel never relies on wall-clock time for security decisions.

Monotonic counters or verified time sources are mandatory.

Any backward movement in time triggers HALT.

HALT must be irreversible with respect to execution.
The kernel may continue to record evidence if physically possible, but it must never execute again without a new, verifiable genesis.

This protects against VM rollback, NTP manipulation, and physical clock tampering.

10. Policy Isolation Alignment (RFC Track B)

Policies are advisory logic.
They must never become authority.

Alignment requires that:

Policy execution occurs in a sandboxed environment.

Policy code cannot access kernel memory, evidence keys, or execution controls.

Policy failure results in denial, not fallback behavior.

If a policy crashes, loops, or misbehaves, the kernel must remain correct.

A kernel that “trusts” policy output is not a kernel — it is a script runner.

11. Inventory & Genesis Alignment (RFC Inventory)

The kernel must be able to prove its own lineage.

Alignment requires that:

Genesis artifacts are immutable and evidence-backed.

Kernel measurements can be verified against genesis commitments.

Recovery and re-keying require quorum proof, not administrator discretion.

This prevents silent replacement or “legitimate-looking” rogue kernels.

12. Test Alignment: How Violations Are Detected

Every alignment rule above must be enforceable by tests.

Tests are not optional documentation.
They are executable law.

If a test fails, the kernel is non-compliant — even if it “works.”

This is why your repository already contains invariant tests, determinism tests, and break-attempt tests. Those are not unit tests. They are compliance probes.

13. Final Alignment Rule

A Meika kernel is compliant if and only if:

All RFC invariants are implemented,

All alignment rules in this document are satisfied,

All conformance tests pass without exception.

Anything less is not “almost Meika.”
It is non-compliant.

Closing Perspective

This document exists to prevent erosion.

Security systems rarely fail because of bad ideas.
They fail because good ideas are slowly compromised by convenience, urgency, and human pressure.

This alignment document is the line that cannot be crossed.
