Conformance Test Specification
(Executable Law for Meika Compliance)

Status: Final
Normative Level: Mandatory
Applies To: All Meika kernel implementations (current and future)

Save Location (important):

docs/formal-specification/conformance-test-specification.md


This placement is correct because:

it sits beside security-invariants.md,

it is part of the formal spec, not general documentation,

auditors will look here immediately after the RFC.

1. Purpose of the Conformance Test Suite

The Meika conformance test suite exists to answer one question only:

Does this implementation obey the law under adversarial conditions?

It is not a unit test suite.
It is not a regression test suite.
It is not a performance test suite.

It is a compliance oracle.

If any conformance test fails, the kernel is non-Meika, regardless of:

feature completeness,

performance,

business requirements,

operational pressure.

This document defines:

what must be tested,

why it must be tested,

what constitutes pass vs violation,

and what failure means.

2. Test Philosophy: Law Over Behavior

Traditional systems test behavior (“does it return the right output?”).
Meika tests invariants (“is it impossible to violate this rule?”).

Therefore, every conformance test follows this structure:

Construct an adversarial or degraded condition

Attempt to force execution

Observe the kernel’s response

Verify invariant preservation

Verify evidence correctness

A test passes only if:

execution is correctly allowed or

execution is denied with proof,
and never because of undefined behavior.

3. Test Categories (Canonical Set)

The conformance suite is divided into seven immutable categories.
Every Meika kernel must pass all seven.

No category may be skipped.
No category may be conditionally disabled.

4. Category I — Determinism & Repeatability
What This Tests

That identical inputs always produce identical outputs, including:

decision outcome,

deny reason,

evidence hash,

Merkle root evolution.

Why This Exists

Non-determinism is a covert channel.
It enables replay ambiguity, timing inference, and legal doubt.

Required Properties

Given the same snapshot, time, policy, and environment:

the decision MUST be bit-for-bit identical.

Reordering non-executed inputs MUST NOT affect results.

Floating-point math MUST NOT exist in decision logic.

Violation Definition

If two identical evaluations produce different hashes, outcomes, or reasons, the kernel fails compliance immediately.

This is why your existing tests like test_kernel_determinism_contract are conformance tests, not “nice-to-have tests”.

5. Category II — Snapshot Integrity & TTL Enforcement
What This Tests

That snapshots are:

immutable,

bounded in time,

and never trusted beyond their validity window.

Why This Exists

This closes TOCTOU attacks and replay abuse.

Required Properties

Snapshots older than the configured TTL MUST cause DENY.

Snapshot mutation MUST be impossible after creation.

Missing snapshot fields MUST cause DENY.

Violation Definition

If execution proceeds with a stale or partially mutated snapshot, the kernel is non-compliant.

No warnings. No retries. No “best effort”.

6. Category III — Precedence & Authority Ordering
What This Tests

That reality (hardware, time, grants) always dominates logic (policy).

Why This Exists

Most breaches occur when logic is allowed to override facts.

Required Properties

Hardware failure beats policy ALLOW.

Time failure beats grant validity.

Grant expiry beats policy intent.

Policy output is advisory only.

Violation Definition

If a policy can cause ALLOW in the presence of a higher-precedence failure, the kernel violates its authority model.

This is an automatic fail.

7. Category IV — Evidence Atomicity & Execution Binding
What This Tests

That execution is cryptographically impossible without prior evidence commitment.

Why This Exists

This eliminates ghost execution, partial execution, and post-hoc logging.

Required Properties

Evidence MUST be assembled before execution.

Evidence MUST be committed successfully.

Execution MUST require an Evidence Commit Receipt.

Evidence commit failure MUST prevent execution.

Violation Definition

If execution can occur when:

evidence storage is unavailable,

commit fails,

or receipt is missing,

the kernel is non-Meika, regardless of intent.

8. Category V — Failure Classification & Closed Behavior
What This Tests

That failures are:

classified,

evidence-backed,

non-recoverable at runtime.

Why This Exists

“Retry” is a bypass strategy in disguise.

Required Properties

Failures MUST be classified into:

Hardware failure

Time failure

Evidence failure

Attestation failure

Policy VM failure

Each failure MUST:

produce a typed DenyReason,

be recorded as evidence,

prevent execution permanently for that evaluation.

Violation Definition

If the kernel retries, masks, or auto-recovers a failure, it fails compliance.

9. Category VI — Side-Channel Resistance (Observable Neutrality)
What This Tests

That denial paths do not leak information through:

timing,

error shape,

resource usage.

Why This Exists

Attackers do not need outcomes if they can infer where failure happened.

Required Properties

All denial paths must be externally indistinguishable within defined tolerance.

Tolerance definitions must be evidence-recorded and non-runtime-configurable.

Error messages must be uniform and non-descriptive externally.

Violation Definition

If an external observer can reliably distinguish failure causes, the kernel leaks information and is non-compliant.

10. Category VII — Time Integrity & HALT Semantics
What This Tests

That time is monotonic, trusted, and irreversible.

Why This Exists

Time rollback is one of the most powerful real-world attacks.

Required Properties

Backward time movement MUST trigger HALT.

HALT MUST permanently prevent execution.

Evidence recording MAY continue if physically possible.

Violation Definition

If execution resumes after time rollback without a new genesis, the kernel fails compliance.

11. Federation & Nexus-Specific Conformance (If Enabled)

If Nexus federation is implemented, additional tests apply:

Peer silence MUST NOT imply approval.

Remote evidence must be verified and embedded.

Partition conditions MUST default to local-only trust.

Failure here results in federation disablement, not degraded trust.

12. Conformance Result Semantics

Conformance is binary.

There is no:

“mostly compliant”

“production exception”

“temporary bypass”

A kernel is either:

Compliant, or

Non-Compliant

Non-compliance invalidates:

security claims,

audit assurances,

and legal defensibility.

13. Relationship to Your Existing Tests

Your current test tree already contains:

determinism tests,

evidence atomicity tests,

precedence tests,

break-attempt tests.

Those are early conformance probes.

This document formalizes them into a closed, enforceable system.

You are not starting from zero.
You are formalizing what you already instinctively built.

Closing Statement

Most systems rely on trust in engineers.
Meika relies on tests that assume engineers will fail.

That is why this document exists.
