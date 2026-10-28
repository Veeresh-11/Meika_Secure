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
| FIX-001 | P0 / critical candidate | Protected-request device binding appeared to pass a dict where `enforce_device_bound_token` hashes bytes-like public-key material. | Reproduce with focused test; use a typed, registered public-key source and canonical key bytes; correct-key succeeds, wrong/missing/malformed key fails closed. | **Resolved in PR #11**, merged as `7bff6e94c0cea2a70ba5abce4370aec756ae5047`; required PR Gate and Deep Scan passed on exact head. Deployment clients must send registered device UUID or registered device identifier in `X-Device-ID`. |
| FIX-002 | P0 / critical | Main WebAuthn routes still call legacy verification helpers; PR #9 says legacy handlers remain mock-style. | No client-provided trust flags accepted as proof; real FIDO2 verifies challenge, origin, RP ID, presence/verification, signature and counter. Test negative cases. | Open |
| FIX-003 | P0 / high | Authentication finish and password login invoked services that committed independently, risking partial session/grant state. | One controlled transaction/unit of work; injected-failure tests prove no partial authenticated state. | **Implemented in draft PR #9; validation pending** (atomic FIDO2 ceremony and policy-gated password-login transaction plus failure-injection tests). |
| FIX-004 | P1 / high | Public-route allowlist includes legacy WebAuthn routes; broad exception mapping masks server failures. | Audited route/method allowlist and exact status-code tests; generic unexpected exceptions return 500, explicit 4xx preserved. | Open |
| FIX-005 | P0 / high | Deep Scan dependency gate fails: reported vulnerable `opentelemetry-api==1.44.0` and dev `black==26.3.1`. | Verify patched releases, update exact pins, clean install, pip check/audit/OSV and tests pass on same SHA. | **Resolved in PR #10**; both required workflows passed on exact head. |
| FIX-006 | P0 / high | `main` reported without branch protection or required checks. | Require PRs and passing CI/security checks; configure ownership/review rules; verify through GitHub settings/API. | Open |
| FIX-007 | P0 / high | In-memory evidence store exists; durable evidence-before-ALLOW path is not yet proven. | Trace live path; ALLOW only after durable evidence commit; storage failure fails closed; restart/concurrency tests. | Open |
| FIX-008 | P0 / high | Middleware passed request transport metadata as principal/device context. | Typed authenticated principal/device context; tenant-aware device lookup; spoofing tests. | **Resolved in PR #11**, merged as `7bff6e94c0cea2a70ba5abce4370aec756ae5047`; regression tests passed. |
| FIX-009 | P1 / high | Policy bootstrap uses a relative path and hard-coded demo relationship tuples. | Stable package-relative policy loading; remove demo authorization from production; startup and tenant-scoped policy tests. | Open |
| FIX-010 | P1 / medium-high | JWT consumer/issuer do not visibly enforce one complete mandatory application claim contract. | Define per-token required claims; enforce at issue and consume; test missing/malformed claims and key rotation. | Open |
| FIX-011 | P1 / medium-high | DB URL built through string interpolation may mishandle special characters in credentials. | Use SQLAlchemy URL.create or correct encoding; tests with reserved characters; no secret logging. | Open |
| FIX-012 | P1 / medium-high | Migration runner sorts all SQL files; exact file set/checksum/drift checks need proof. | Detect missing, unexpected, duplicate-prefix, out-of-order and checksum-drift migrations; negative tests. | Open |
| FIX-013 | P1 / medium | Generic exception handling returns misleading 400/403 statuses. | Contract tests distinguish 401/403/4xx validation from 500/503; no sensitive error leakage. | Open |
| FIX-014 | P1 before release / medium | No Dockerfile detected, so image build/Trivy image scan were skipped. | Before container release, add hardened image and require build/scan; otherwise document not-applicable until release artifact exists. | Open |
| FIX-015 | P1 / medium | Naive UTC patterns remain in reviewed auth/service/model code despite timestamp-hygiene goal. | Standardize timezone handling or document adapter contract; Ruff DTZ checks and pytest warnings-as-errors pass without broad suppression. | Open |
| FIX-016 | P0 / medium | Challenge validate and consume are separate operations; concurrent replay race is plausible. | Atomic consume with row lock or compare-and-set; concurrent test proves exactly one request succeeds. | **Implemented in draft PR #9; validation pending** (compare-and-set consume, single-use enrollment-token partial unique index, race tests). |

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


## Progress update — 2026-10-28 11:25 IST

- Architecture/remediation map added as [SVG](../architecture/meika-secure-id-architecture-remediation-map.svg) and embedded in [architecture README](../architecture/README.md).
- Dependency remediation PR #10 was merged after both required workflows passed on head `3219ee69e775a4d74378f1b75a15ec9357f75138` (PR Security Gate run 40633839431 and Deep Security Scan run 40633839414). The deep scan's pip-audit, OSV-Scanner and final enforcement gate passed. Image build/container scan and SonarQube remain skipped/not configured in that run.
- FIX-001 implementation is now proposed in [PR #11](https://github.com/Veeresh-11/Meika_Secure/pull/11): resolve device key from active tenant-scoped WebAuthn credentials, validate signed JWT binding, use typed DeviceSnapshot, and reject invalid key types. Regression tests added for middleware, resolver behavior and malformed key material.
- PR #11 validation is still running: Deep Security Scan run 40641128892 is in progress; PR Security Gate run 40641128914 is pending. FIX-001 remains **open** until both pass and key/header representation is reviewed against deployment configuration.


## Progress update — 2026-10-28 11:40 IST

- Re-checked PR #11 at head `98d696e740ce9eda7bffa9ba91ec5fe11bef4bd5`. The deep scan passed, but the PR Security Gate found **2 failed tests out of 1,258** (coverage 86.29%, above the 85% threshold) and **2 blocking Semgrep findings**. The test failures were caused by a 31-byte HS256 key in the test helper, triggering `InsecureKeyLengthWarning` under warning-as-error policy. Semgrep flagged unverified JWT claim decoding and a hardcoded test JWT secret.
- Updated the FIX-001 implementation on branch `fix/fix001-registered-device-key-binding` to remove unverified-claim decoding entirely: it now selects candidate records from the requested device identifier, then verifies the JWT against persisted active, non-revoked, tenant-matched credentials before trusting `sub`/`did`. Added an exact request-device match guard. Test JWT keys are now generated ephemerally at 32 bytes, and malformed-token coverage fails closed.
- Latest PR #11 head: `ada5b542110fefde3fd76bb0741d710c17a885a2`. New validation is underway: [PR Security Gate run 40642202499](https://github.com/Veeresh-11/Meika_Secure/actions/runs/40642202499) pending and [Deep Security Scan run 40642202505](https://github.com/Veeresh-11/Meika_Secure/actions/runs/40642202505) in progress. FIX-001 remains **open** until both workflows pass and the key representation/device-header contract is confirmed.
- Started FIX-002 review by examining PR #9 and current `app/api/auth.py`. The draft adds a separate `/fido2` router with real ceremony-verification functions, but legacy `/auth/webauthn/*` handlers remain present on `main`; the registration request model still accepts client-provided `hardware_backed=True` and `attestation_verified=True` flags. Do not merge PR #9 as-is. Next action is to map router inclusion and all callers, then remove/disable legacy trust-flag paths or route them through the single verified FIDO2 implementation, with negative tests.


## Progress update — 2026-10-28 12:05 IST

- FIX-001 PR #11 remains open and unmerged at candidate `ada5b542110fefde3fd76bb0741d710c17a885a2`. The latest PR Security Gate run `40642202499` and Deep Security Scan `40642202505` were still in progress at the last check. The updated code removes unverified JWT claim lookup and short/hardcoded test keys, but final pass status and production key/header compatibility are not yet confirmed.
- Continued FIX-002 on draft PR #9 (`feature/real-fido2-webauthn`). Added optional `commit=True` controls to device, WebAuthn credential, session, and grant service methods so existing callers retain behavior while the FIDO2 ceremony can opt into a caller-owned transaction.
- Refactored FIDO2 registration to consume its challenge, create the device and credential, and persist the sign count in one transaction. Refactored FIDO2 authentication to consume the challenge, update credential metadata, create session/grant, update device/grant activity, issue the token, and commit once before returning it. Exceptions roll back and do not return an access token.
- Added regression tests for atomic challenge-consumption behavior and race rejection in `app/test_fido2_routes.py`. Latest PR #9 head: `0a8af7bbc45fb91483718b2bab2abd248871f09f`. These changes are committed to the draft PR branch, but CI has not yet reported a run for the latest head in the current check.
- Outstanding review items: run both required workflows against the latest PR #9 head; add/confirm failure-injection coverage for registration/authentication rollback; update the stale PR #9 base safely; verify that `public_key` stored as base64url for WebAuthn verification is intentionally encoded consistently for device-bound JWT HMAC signing; and finish PR #11 key/header compatibility review.
- No PR was merged in this checkpoint. FIX-001 and FIX-002 remain open until CI and targeted tests prove the behavior.


## Progress update — 2026-10-28 12:20 IST

- FIX-002 draft PR #9 now has latest head `1119f3f92ea8e164b136df13a31911b279096209`. The change set includes transaction-aware service methods, atomic challenge consumption plus related registration/authentication writes, rollback paths, and tests for challenge races and registration failure rollback. GitGuardian reports no secrets for the latest head; the standard PR Security Gate and Deep Security Scan have not yet appeared for this head, so functional/security CI is still **unverified**.
- The atomicity tests are committed but have not been executed locally in this session. The rollback regression injects a simulated device insert failure after challenge consumption and asserts rollback and no commit. Follow-up should add/confirm an analogous authentication failure test and execute the exact candidate against the required workflows.
- FIX-001's PR #11 workflows remain in progress: PR Security Gate is in the `Tests + Coverage` step; Deep Security Scan is in `OSV-Scanner`. Earlier completed jobs on the gate (critical Python quality, workflow security, dependency review, secret scan) passed; scorecard was skipped. No final conclusions yet.
- Neither PR #9 nor PR #11 has been merged. Do not mark FIX-001/FIX-002 complete until required checks pass on their exact latest heads, all transaction failure tests pass, and key/device identity contract is reviewed.


## Progress update — 2026-10-28 12:30 IST

- FIX-002 draft PR #9 latest code head: `53a1cc8fd99f9c86c742aa3452de29d89ebad555`. Added a PostgreSQL partial unique index on enrollment-purpose challenges so concurrent registration-options requests cannot reuse the same enrollment-token `jti`; the route translates a unique-index collision into a generic 401 and rolls back. Added migration `018_enforce_single_use_webauthn_enrollment.sql`, mirrored the partial index in SQLAlchemy metadata (PostgreSQL and SQLite test dialects), and added `018` plus the index to schema validation requirements.
- Added route regression tests for rollback after simulated registration device-write failure, rollback after simulated authentication credential-update failure, challenge-consumption race rejection, and concurrent enrollment-token reuse. Latest GitGuardian scan for the prior head passed; these newest commits still require test/security CI.
- CI status for PR #9: no PR Security Gate or Deep Security Scan run is currently associated with the latest draft head; only GitGuardian checks are appearing. Do not interpret that as tests passing. Resolve the reason workflows are not running (or run them via an approved CI mechanism) before merge.
- PR #11 still has no final result from the latest required runs. The PR Security Gate is in tests/coverage and Deep Security Scan is in progress. FIX-001 remains open.
- Outstanding: run checks on the exact latest heads; ensure the schema migration applies cleanly to an isolated PostgreSQL test DB; test SQLite metadata creation; safely bring PR #9 up to date with current `main`; and verify all related routes and service callers. No merge performed.


## Progress update — 2026-10-28 12:35 IST

- **FIX-001 and FIX-008 merged to main** in squash commit `7bff6e94c0cea2a70ba5abce4370aec756ae5047` from PR #11. Exact PR head `ada5b542110fefde3fd76bb0741d710c17a885a2` passed the PR Security Gate: **1,258 passed, 0 skipped, 0 failures, 86.55% coverage** (85% required). Dependency audit, Bandit, Semgrep, Trivy filesystem/config, red-team tests and CodeQL passed. Deep Security Scan passed. Scorecard was skipped.
- Reviewed key-byte consistency against the current token issuer: both issuer and resolver encode the persisted WebAuthn public-key string as UTF-8 for device-binding hash material. The request's `X-Device-ID` must equal the registered device UUID or its persisted `device_identifier`; this is enforced in code, but deployment clients have not been inspected.
- PR #9 and PR #12 were closed as superseded; canonical PR #13 (`fix/fido2-atomic-validation-final`, current head `f599484db9cab78b3ee992f81f73efe79d0f7a5d`) carries the current candidate: atomic WebAuthn registration/authentication transactions; rollback on injected failures; single-use enrollment-token partial unique index plus migration 018/schema-validator contract; password-login transaction deferred until policy ALLOW; and removal of client-asserted device trust signals from the password-login policy context.
- PR #13 is open and unmerged; PR #9 and #12 are closed as superseded with no commits discarded. GitGuardian passed on earlier candidate heads, but the standard PR Gate and Deep Security Scan have not been associated with PR #13's exact head. Therefore FIX-002, FIX-003 and FIX-016 remain **validation pending**, not resolved. The latest password-login transaction/trust changes have not been exercised by required CI.
- Next: get PR #9 validated on its exact latest head, safely update it against the now-current main, fix all new failures, then merge only after both required workflows and migration/bootstrap tests pass. Continue with FIX-004 and FIX-007 after this gate.


- PR #13 was opened on 2026-10-28 as the canonical validation PR for the atomic WebAuthn candidate; its latest head is `f599484db9cab78b3ee992f81f73efe79d0f7a5d`. PR #9 and PR #12 were closed as superseded. No PR-triggered PR Security Gate or Deep Security Scan run is visible for PR #13. Main-branch workflows run on the merge/docs commits, but those runs do not validate PR #13's code.


- Dependency preservation check on PR #13 found its inherited requirements file would otherwise have reverted PR #10's patched OpenTelemetry pins. Fixed the latest branch head to retain all `1.45.1` OpenTelemetry pins and add `webauthn==3.0.0`. This exact latest head has not been scanned by pip-audit/OSV or the full required CI.


- Final WebAuthn transaction review added one more failure boundary: the limited enrollment JWT is now signed before committing password-login state; if signing fails, the transaction rolls back. Added a regression test asserting rollback/no commit on signing failure. PR #13 latest head is `f599484db9cab78b3ee992f81f73efe79d0f7a5d`.
- GitHub Actions trigger issue remains unresolved for PR #13: GitGuardian checks appear, but the two required workflows do not start on the PR head. Do not infer a pass from main-branch push workflows; they validate main commits, not the unmerged WebAuthn branch. PR #13 must remain unmerged until exact-head CI is available and passes.
