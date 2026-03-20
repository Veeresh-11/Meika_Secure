# Meika Authenticator — Architecture Overview

## Purpose

This document explains how Meika enforces Zero Trust at runtime,
and where responsibilities are intentionally placed.

---

## End-to-End Enforcement Flow

nbound Request
↓
Intent Extraction (required)
↓
Authentication (phishing-resistant)
↓
Device Identity Verification
↓
Device Posture Evaluation
↓
Policy Evaluation (auth + device + risk + containment)
↓
Grant Enforcement (if privileged)
↓
Containment Check
↓
Evidence Write (pre-execution)
↓
Execution
↓
Evidence Write (post-execution)


**No step may be skipped.**

---

## Core Enforcement Components

### Policy Enforcer
- Evaluates all policies
- Determines allow / restrict / deny
- Never executes business logic

### Grant Enforcer
- Enforces JIT and investigation grants
- Ensures scope, expiry, and revocation
- Prevents privilege accumulation

### Containment Enforcer
- Detects malicious or unsafe behavior
- Revokes all privilege immediately
- Overrides all other decisions

### Evidence Writer
- Produces immutable audit records
- Blocks execution on failure
- Makes decisions provable

---

## Architectural Non-Goals

Meika intentionally avoids:
- Session management
- UI-based authorization
- Implicit “trusted mode”
- Stateful privilege caching

These are considered unsafe.

---

## Design Rule

If authorization logic exists outside `app/security`,
the system is broken by definition.
