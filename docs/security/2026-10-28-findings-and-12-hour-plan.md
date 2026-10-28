# Meika Secure ID — Security Findings Tracker and 12-Hour Work Plan

**Date:** 2026-10-28  
**Repository:** https://github.com/Veeresh-11/Meika_Secure  
**Baseline main SHA reviewed:** `3d6c39aa0c58b33444471da58de42cca3b6dc8f8`  
**Latest Deep Scan run reviewed:** https://github.com/Veeresh-11/Meika_Secure/actions/runs/40468064136

## Status and rules

This is a static source + CI-artifact review, not a full local checkout, runtime reproduction, or penetration test. Findings remain open until reproduced, fixed, regression-tested, and validated on the exact candidate SHA. Do not suppress scanner findings, downgrade blocking gates, reduce coverage, or ignore warnings. Do not reset/clean the user's worktree or run destructive operations against production DB `meika_secure_id`. Use the isolated test DB/cluster only; verify DSNs before running tests and never paste secrets into logs/chat.

Latest Deep Scan failed its final gate: pip-audit reported two dependency vulnerabilities and OSV reported one (OpenTelemetry API 1.44.0; Black 26.3.1 in dev dependencies, according to the report). ZAP had no high/medium alerts, Nuclei no critical/high findings, Schemathesis had zero failures, Bandit had no medium/high findings, and Trivy config had no high/critical findings. Image scan was skipped because no Dockerfile was detected. A green individual scanner does not override the failed final gate.

## Findings backlog

| ID | Priority | Finding | Acceptance criteria | Status |
|---|---|---|---|---|
| FIX-001 | P0 / critical candidate | Protected-request device binding appears to pass a dict where `enforce_device_bound_token` hashes bytes-like public-key material. | Reproduce with focused test; use a typed, registered public-key source and canonical key bytes; correct-key succeeds, wrong/missing/malformed key fails closed. | Open |
| FIX-002 | P0 / critical | Main WebAuthn routes still call legacy verification helpers; PR #9 says legacy handlers remain mock-style. | No client-provided trust flags accepted as proof; real FIDO2 verifies challenge, origin, RP ID, presence/verification, signature and counter. Test negative cases. | Open |
| FIX-003 | P0 / high | Authentication finish invokes services that commit independently, risking partial session/grant state. | One controlled transaction/unit of work; injected-failure tests prove no partial authenticated state. | Open |
| FIX-004 | P1 / high | Public-route allowlist includes legacy WebAuthn routes; broad exception mapping masks server failures. | Audited route/method allowlist and exact status-code tests; generic unexpected exceptions return 500, explicit 4xx preserved. | Open |
| FIX-005 | P0 / high | Deep Scan dependency gate fails: reported vulnerable `opentelemetry-api==1.44.0` and dev `black==26.3.1`. | Verify patched releases, update exact pins, clean install, pip check/audit/OSV and tests pass on same SHA. | Open |
| FIX-006 | P0 / high | `main` reported without branch protection or required checks. | Require PRs and passing CI/security checks; configure ownership/review rules; verify through GitHub settings/API. | Open |
| FIX-007 | P0 / high | In-memory evidence store exists; durable evidence-before-ALLOW path is not yet proven. | Trace live path; ALLOW only after durable evidence commit; storage failure fails closed; restart/concurrency tests. | Open |
| FIX-008 | P0 / high | Middleware appears to pass one transport dict as principal ID, device ID and device object. | Typed authenticated principal/device context; tenant-aware device lookup; spoofing tests. | Open |
| FIX-009 | P1 / high | Policy bootstrap uses a relative path and hard-coded demo relationship tuples. | Stable package-relative policy loading; remove demo authorization from production; startup and tenant-scoped policy tests. | Open |
| FIX-010 | P1 / medium-high | JWT consumer/issuer do not visibly enforce one complete mandatory application claim contract. | Define per-token required claims; enforce at issue and consume; test missing/malformed claims and key rotation. | Open |
| FIX-011 | P1 / medium-high | DB URL built through string interpolation may mishandle special characters in credentials. | Use SQLAlchemy URL.create or correct encoding; tests with reserved characters; no secret logging. | Open |
| FIX-012 | P1 / medium-high | Migration runner sorts all SQL files; exact file set/checksum/drift checks need proof. | Detect missing, unexpected, duplicate-prefix, out-of-order and checksum-drift migrations; negative tests. | Open |
| FIX-013 | P1 / medium | Generic exception handling returns misleading 400/403 statuses. | Contract tests distinguish 401/403/4xx validation from 500/503; no sensitive error leakage. | Open |
| FIX-014 | P1 before release / medium | No Dockerfile detected, so image build/Trivy image scan were skipped. | Before container release, add hardened image and require build/scan; otherwise document not-applicable until release artifact exists. | Open |
| FIX-015 | P1 / medium | Naive UTC patterns remain in reviewed auth/service/model code despite timestamp-hygiene goal. | Standardize timezone handling or document adapter contract; Ruff DTZ checks and pytest warnings-as-errors pass without broad suppression. | Open |
| FIX-016 | P0 / medium | Challenge validate and consume are separate operations; concurrent replay race is plausible. | Atomic consume with row lock or compare-and-set; concurrent test proves exactly one request succeeds. | Open |

## Today's 12-hour execution plan (12 focused hours; sequence is gated by test results)

1. **Hour 1 — Preserve and establish baseline.** Inspect local `git status`, current branch/SHA and existing diffs; verify the isolated test DB configuration. Record CI runs on the exact SHA. No reset/clean and no production DB writes.
2. **Hour 2 — Fix dependency audit findings.** Confirm patched package versions from authoritative advisories, update `requirements.txt` and `requirements-dev.txt` pins, then clean-install in a disposable venv. Run `pip check`, pip-audit and OSV scan.
3. **Hours 3–4 — Reproduce FIX-001.** Add focused tests for the device-binding contract and protected-route path. Patch typed key resolution only after confirming registration/key storage design. Run focused auth/security tests.
4. **Hours 5–6 — WebAuthn P0 review.** Inspect PR #9 current head and the live route imports. Make one authoritative production ceremony path; reject trust flags/mock verification. Test challenge/user/tenant/purpose binding, origin/RP ID, signature failure, expiry and replay. Do not merge the draft PR blindly.
5. **Hour 7 — Challenge race (FIX-016).** Implement atomic challenge consumption in a transaction/row-lock or compare-and-set; add a concurrent replay test.
6. **Hour 8 — Authentication transaction (FIX-003).** Map service commit boundaries and add failure injection. If scope cannot be completed safely, record exact failing boundary and leave it open rather than pretending atomicity.
7. **Hour 9 — Evidence and SecurityContext (FIX-007/008).** Trace live request-to-kernel-to-store path; test fail-closed evidence persistence and typed tenant-bound principal/device values.
8. **Hour 10 — Static/configuration hardening.** Address the smallest verified issues among FIX-009, FIX-010, FIX-011, FIX-013 and FIX-015; run compile, Ruff and warning-as-error checks.
9. **Hour 11 — Migration and CI review.** Revalidate PR #4 and #5 at their current heads, migration exactness and required scanner gate; do not rely on stale PR-body status claims. Confirm branch-protection settings separately.
10. **Hour 12 — Final validation and handoff.** Run focused tests, full suite on isolated DB, `pytest -W error`, Ruff, `pip check`, dependency scanners and clean bootstrap where feasible. Inspect `git diff --check`, review every diff, commit only tested changes to a feature branch, open/update PR, and report exact SHA/results/remaining blockers.

### Priority if time is constrained

The first deliverable is a verified dependency-audit fix plus regression test for FIX-001. Next are WebAuthn production-path assurance and atomic challenge consumption. Do not merge a code patch solely to meet the clock. If a fix fails tests, keep it isolated and continue investigating; report unfinished items explicitly.

## Existing GitHub work to re-check

- PR #4 — DB-012 migration bootstrap failure semantics: https://github.com/Veeresh-11/Meika_Secure/pull/4
- PR #5 — CI workflow security audit: https://github.com/Veeresh-11/Meika_Secure/pull/5
- PR #8 — Persist WebAuthn clone revocation: https://github.com/Veeresh-11/Meika_Secure/pull/8
- PR #9 — Real FIDO2/WebAuthn verification (draft): https://github.com/Veeresh-11/Meika_Secure/pull/9
- Issue #6 — Security validation expansion: https://github.com/Veeresh-11/Meika_Secure/issues/6
- Issue #3 — Reproducible CI outcomes: https://github.com/Veeresh-11/Meika_Secure/issues/3

## Suggested safe local checks

First inspect state:
```bash
git status --short --branch
git log -8 --oneline --decorate
```

Then, in the project checkout and isolated test environment only:
```bash
python -m compileall -q app scripts
ruff check --select E9,F63,F7,F82,DTZ003 app scripts
git diff --check
python -m pip check
pip-audit -r requirements.txt
pip-audit -r requirements-dev.txt
pytest -q -W error
```

Verify exact test paths and database DSNs before use. Never point reset/bootstrap tests at the production `meika_secure_id` database.

**Definition of done:** focused regression tests and full required suite pass on the exact candidate SHA; zero unexplained project warnings; no unresolved high/critical findings or ignored scanner failures; DB bootstrap/rollback/tenant isolation verified; all CI results and residual risks documented. Findings are not marked resolved by documentation alone.
