RFC-MEIKA-DOC-DES&CRE-001
Meika Secure ID — Deterministic Execution Governance

Status: Final / Frozen

1. Why Meika Exists (Problem Framing)

Every security system ultimately fails at the same boundary: the moment where a decision becomes an action. Traditional systems decide first and log later. Meika exists because that ordering is fundamentally unsafe.

In conventional IAM, Zero Trust, or policy-based systems, the authorization decision is made in memory, execution happens immediately, and logs are written afterward as a best-effort activity. This creates an irreducible gap: if execution succeeds but logging fails, the system has already caused irreversible change without proof. That gap is where attackers live, auditors fail systems, and post-incident reconstruction collapses into guesswork.

Meika was designed to eliminate that gap entirely by redefining what it means for an action to be allowed. In Meika, execution is not permitted by a decision. Execution is permitted by evidence that the decision already exists and is committed.

This inversion is the core of the system.

2. Ontology: What Meika Is (and Why That Matters)

Meika is a deterministic security kernel that governs execution. It is intentionally not an identity system, not a role system, not a session manager, and not a policy engine. Those systems manage who someone is or what they might want to do. Meika governs whether the universe is allowed to change as a result.

This distinction is critical. Identity systems are about attribution. Meika is about causality.

By refusing to own identity, roles, or privileges, Meika avoids inheriting trust assumptions that are historically fragile. Identity systems assume credentials remain secure. Role systems assume administrators behave correctly. Sessions assume continuity of trust over time. Meika assumes none of these.

Instead, Meika treats every request as an untrusted proposal to cause change.

3. Execution: The Central Concept

Execution is the only thing Meika cares about, so it is defined narrowly and precisely.

Execution is any action that produces an irreversible or externally observable effect. If the outside world can tell that something happened, or if the system cannot fully revert to its prior state, then execution has occurred. Writing to disk, sending packets, issuing tokens, allocating resources, or signing cryptographic material are all execution.

By contrast, computation that does not escape the kernel boundary is not execution. Parsing input, evaluating policies, calculating risk, constructing evidence, or simulating outcomes are all preparatory activities. They are permitted to fail freely because they do not change reality.

This definition exists to prevent category errors. Without it, engineers accidentally treat logging as optional, auditors conflate computation with execution, and attackers exploit undefined gray areas.

4. Global Laws and Why They Are Absolute

Meika enforces a small number of global invariants because invariants are the only things that survive scale, complexity, and human pressure.

Denial is the default because allowing under uncertainty always increases attack surface. Evidence is mandatory because without evidence there is no proof, and without proof there is no security claim. Evidence is append-only because mutable history is indistinguishable from falsified history.

Snapshots are used instead of live objects because live state changes during evaluation introduce race conditions that cannot be reasoned about formally. Determinism is favored over convenience because non-deterministic systems cannot be audited or reproduced. Safety is favored over availability because irreversible harm is worse than temporary denial.

Failures are explicitly classified because unclassified failures are quietly retried, and retries are how systems are bypassed. In Meika, a failure is a terminal fact, not a suggestion.

5. The Execution Workflow (Deep Walkthrough)

When an intent arrives at Meika, it is not treated as a request to be fulfilled. It is treated as an untrusted claim that execution should occur.

The kernel first constructs an immutable snapshot of all relevant state. This snapshot is not just a data structure; it is a temporal contract. By enforcing a strict time-to-live on snapshots, Meika ensures that decisions are bound to a narrow window of reality. If the world changes after the snapshot expires, the decision is invalidated automatically. This closes the class of attacks where an attacker races system state after approval but before execution.

Precedence enforcement follows. This is not policy evaluation; it is reality evaluation. Hardware attestation, time integrity, revocation state, and grant validity are checked first because these are facts of the physical or cryptographic world. Policy is evaluated last because policy is opinionated logic that can be wrong, compromised, or malicious.

Policy execution occurs in a sandbox and is treated as advisory. This is deliberate. Policy engines are historically one of the most exploited components of security systems because they are expressive, mutable, and complex. Meika strips them of authority entirely.

Once evaluation completes, the kernel does not execute. Instead, it constructs an evidence record that describes exactly what was evaluated, what inputs were used, and what outcome was reached. This evidence is then committed to a Merkle-aggregated store.

Only after the evidence is successfully committed does the kernel receive an Evidence Commit Receipt. This receipt is not a log entry. It is the cryptographic key that unlocks execution. Without it, the kernel cannot execute even if it “wants” to.

This ordering ensures that execution is impossible without prior proof.

6. Atomicity: Why Evidence Comes First

The atomicity law exists because partial failure is the normal state of distributed systems. Storage fails. Networks partition. Power drops. Processes crash.

In traditional systems, execution happens first and evidence is best-effort. In Meika, evidence happens first and execution is conditional.

This reverses the failure modes. If evidence fails, execution never occurs. If execution occurs, evidence already exists. There is no interleaving where damage can occur without proof.

This is the single most important property of Meika.

7. Time, HALT, and Irreversibility

Meika treats time as a security primitive. It does not trust wall clocks because wall clocks can be manipulated. It uses monotonic sources that can only move forward.

If time moves backward, the kernel halts. Halt is not a restart. Halt is a permanent refusal to execute. This is intentional. If time integrity is compromised, the system cannot reason about freshness, expiration, or causality. Continuing execution under those conditions would be reckless.

Evidence may still be recorded during halt if physically possible, because understanding failure is valuable even when execution is forbidden.

8. Inventory and Memory of Self

The Meika Inventory exists because systems that cannot remember their own origin cannot prove their legitimacy. Genesis artifacts anchor the system’s identity in time. They allow any future observer to verify that the running kernel descends from an authorized beginning and has not been replaced silently.

This prevents a powerful class of attacks where a perfectly valid—but unauthorized—kernel is introduced with a new trust root.

9. Humans and the Absence of Authority

Humans are allowed to observe and request, but never to decide. This is not a philosophical stance; it is a defensive one. Every historical “emergency override” eventually becomes a permanent vulnerability.

By refusing to encode human authority into the kernel, Meika ensures that social engineering cannot override cryptography, evidence, or physics.

10. What This Document Guarantees

If an execution occurs, Meika can always prove:

what was evaluated

when it was evaluated

why it was allowed

under which physical and cryptographic conditions

If an execution does not occur, Meika can prove why it was denied.

There is no silent success and no unexplained failure.

Final Perspective

This document does not describe a product. It defines a law of operation. Implementations may vary, but deviation from this document is not optimization—it is non-conformance.

Meika is not trying to be flexible. It is trying to be correct.
