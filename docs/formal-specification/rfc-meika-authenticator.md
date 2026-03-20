RFC-MEIKA-AUTH-001
Meika Authenticator Protocol & Human Interaction Specification

Status: Final
Normative Level: Mandatory
Applies To:

Desktop Authenticator

Mobile Authenticator

Hardware-bound Authenticator variants

Any system that signs Intent for Meika Kernel

Save Location:

docs/formal-specification/rfc-meika-authenticator.md


This belongs under formal-specification because:

the Authenticator is a security boundary, not an app,

it directly participates in execution causality,

it holds cryptographic authority.

0. Purpose and Non-Goals

The Meika Authenticator exists to perform one function only:

To transform human intent into cryptographically verifiable authority, without introducing trust shortcuts.

It is not:

an IAM system,

a password manager,

a session manager,

a policy engine,

a recovery console.

The Authenticator does not grant access.
It does not decide outcomes.
It does not bypass the kernel.

It binds a human decision to an immutable execution request.

1. Trust Model

The Authenticator is a constrained authority.

It is trusted to:

hold private keys securely,

present intent clearly to a human,

sign intent accurately.

It is not trusted to:

evaluate policy,

decide safety,

override kernel decisions,

interpret outcomes.

If the Authenticator is compromised, the kernel must still fail closed.

This asymmetry is deliberate.

2. Authenticator Threat Model

The Authenticator explicitly assumes:

The user may be socially engineered

The host OS may be compromised

Malware may observe UI interactions

Network traffic may be monitored

The kernel may be unreachable

Therefore:

no silent actions are permitted,

no background signing is permitted,

no persistent authorization is permitted.

Every signature must correspond to a visible, human-confirmed intent.

3. Identity & Key Material

Each Authenticator instance SHALL possess a non-exportable private key.

Key requirements:

Generated inside a hardware-backed secure element (TPM, Secure Enclave, HSM)

Marked non-extractable

Bound to device identity

Never transmitted

Never backed up in plaintext

Loss of the Authenticator device means loss of signing capability, not system compromise.

Recovery is governed elsewhere (Inventory / Genesis), not here.

4. Intent: Formal Definition

An Intent is a signed declaration of a human’s willingness to request execution.

Intent MUST include:

Actor identity reference

Target operation description

Scope and boundaries

Explicit consequences

Validity window

Nonce

Kernel challenge reference

Intent MUST NOT include:

Policy assumptions

Execution guarantees

Authorization claims

Intent expresses desire, not permission.

5. Transactional Intent Boundary

To avoid computational abuse and UX failure, intent is transaction-scoped, not packet-scoped.

A transaction may include:

multiple I/O operations

multiple objects

bounded repetition

But it MUST:

be finite

be human-understandable

declare its limits

Example (conceptual):

“Authorize upload of 50 files to Project X within the next 2 minutes.”

This results in:

one signature

one evidence record

bounded execution

This prevents:

CPU exhaustion

intent spamming

invisible privilege expansion

6. User Interaction Requirements

Every intent signing event MUST:

Present a human-readable summary

Clearly state irreversible effects

Require deliberate confirmation

Be resistant to click-through fatigue

The Authenticator SHALL NOT:

auto-approve

batch silently

reuse prior consent

infer intent

There is no “remember me”.

7. Kernel Verification & Remote Attestation

Before signing any intent, the Authenticator MUST verify:

Kernel identity

Kernel integrity

Kernel freshness

This is achieved via:

Measured boot attestation

Nonce-based challenge

Continuous freshness heartbeats

If verification fails:

intent signing is refused

no degraded mode exists

The Authenticator must never sign intent for an unverified kernel.

8. Evidence Awareness (But Not Authority)

The Authenticator MAY display:

Evidence hashes

Merkle root references

Decision receipts

But it MUST NOT:

interpret outcomes

claim success

retry execution

modify intent post-signing

The kernel remains the only authority.

9. Failure Handling

If any of the following occur:

kernel unreachable

attestation failure

time skew

integrity mismatch

evidence receipt missing

The Authenticator SHALL:

refuse to sign

surface a clear failure message

log locally for diagnostics

take no corrective action

The Authenticator does not attempt recovery.

10. Offline Behavior

Offline mode is restricted by design.

The Authenticator MAY:

prepare intent drafts

display prior receipts

It MUST NOT:

sign intent

cache authorization

predict kernel outcomes

Offline signing is forbidden.

11. Human Capability Boundary

Humans interacting through the Authenticator MAY:

observe state

initiate signed intent

revoke their own keys

Humans MUST NOT:

override decisions

bypass evidence

modify kernel state

alter execution ordering

This prevents operator privilege creep.

12. Side-Channel Considerations

The Authenticator SHALL:

normalize response timing

avoid error shape differentiation

mask kernel failure causes when displayed

The goal is:

no oracle for attackers

no feedback for probing

13. Relationship to Other Documents

This RFC depends on:

Global Invariants

Track A (Kernel)

Track C (Evidence)

Inventory RFC

It does not replace them.

The Authenticator is a boundary object, not a control plane.

14. Explicit Non-Features

The Authenticator SHALL NEVER support:

Sessions

Standing admin

Emergency overrides

Runtime bypass

Policy editing

Kernel control

Any implementation offering these is non-compliant.

15. Security Posture Summary

The Authenticator enforces:

Human-time decision making

Cryptographic non-repudiation

Hardware-anchored identity

Zero trust in itself

It is intentionally inconvenient.

Convenience is an attack surface.

Closing Statement

Most systems try to make humans invisible.
Meika makes humans explicit, accountable, and bounded.

The Authenticator is not a product feature.
It is the human interface to causality.
