#!/usr/bin/env python3
"""Score the PR gate using step outcomes and warnings from the run logs.

Each defined check starts at 100 points. Failed, cancelled, or
skipped required checks receive zero. Warning penalties are deducted from the
total score by severity. Deliberate database errors are not counted as CI
warnings; tests must prove those negative cases are expected.
"""
from __future__ import annotations

import os
import re
import sys
import zipfile
from pathlib import Path

CHECKS = [
    ("Secret scan", "SECRET_SCAN"),
    ("Dependency review", "DEPENDENCY_REVIEW"),
    ("Checkout", "CHECKOUT"),
    ("Redis readiness", "REDIS_READY"),
    ("Python setup", "SETUP_PYTHON"),
    ("CodeQL initialization", "CODEQL_INIT"),
    ("Dependency installation", "DEPENDENCIES"),
    ("PostgreSQL readiness", "POSTGRES_READY"),
    ("Primary database bootstrap", "DB_BOOTSTRAP"),
    ("Exact migration chain", "MIGRATION_CHAIN"),
    ("PostgreSQL version check", "POSTGRES_VERSION"),
    ("Pytest database bootstrap", "TEST_DB_BOOTSTRAP"),
    ("Dependency vulnerability audit", "DEPENDENCY_AUDIT"),
    ("Bandit SAST", "BANDIT"),
    ("Semgrep SAST", "SEMGREP"),
    ("Tests, coverage, warnings-as-errors", "TESTS"),
    ("Trivy filesystem scan", "TRIVY_FS"),
    ("Trivy configuration scan", "TRIVY_CONFIG"),
    ("Red-team tests", "RED_TEAM"),
    ("CodeQL analysis", "CODEQL"),
]
POINTS_PER_CHECK = 100
MAX_SCORE = len(CHECKS) * POINTS_PER_CHECK

ANNOTATION_WARNING = re.compile(r"(?:##\[warning\]|::warning::)", re.IGNORECASE)
PYTHON_RUNTIME_WARNING = re.compile(
    r"\b(?:DeprecationWarning|PendingDeprecationWarning|ResourceWarning|"
    r"RuntimeWarning|FutureWarning|SyntaxWarning|UserWarning):"
)
LOG_WARNING = re.compile(r"(?:^|\s)(?:WARNING|WARN)\s*:", re.IGNORECASE)


def warning_events(zip_path: Path) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    try:
        with zipfile.ZipFile(zip_path) as archive:
            for member in archive.namelist():
                if not member.lower().endswith((".txt", ".log")):
                    continue
                try:
                    text = archive.read(member).decode("utf-8", errors="replace")
                except (KeyError, OSError):
                    continue
                for line in text.splitlines():
                    if ANNOTATION_WARNING.search(line):
                        found.append((line.strip(), 15))
                    elif PYTHON_RUNTIME_WARNING.search(line):
                        found.append((line.strip(), 10))
                    elif LOG_WARNING.search(line):
                        found.append((line.strip(), 5))
    except (OSError, zipfile.BadZipFile) as exc:
        raise RuntimeError(f"Unable to read workflow log archive: {exc}") from exc

    unique: dict[str, int] = {}
    for line, penalty in found:
        key = re.sub(r"^\d{4}-\d\d-\d\dT[^ ]+\s+", "", line)
        unique[key] = max(unique.get(key, 0), penalty)
    return [(line, penalty) for line, penalty in unique.items()]


def main() -> int:
    if len(sys.argv) not in (1, 2):
        print("Usage: score_pr_gate.py [workflow-log-zip]", file=sys.stderr)
        return 2

    scores: list[tuple[str, str, int]] = []
    for label, env_name in CHECKS:
        outcome = os.environ.get(env_name, "").strip().lower()
        points = POINTS_PER_CHECK if outcome == "success" else 0
        scores.append((label, outcome or "missing", points))

    # Same-run workflows cannot download their own complete log archive:
    # GitHub only publishes it after the entire workflow finishes. Warning
    # enforcement is therefore done at source (pytest -W error and strict
    # scanner steps). Parse a log archive only when one is supplied externally.
    warnings = warning_events(Path(sys.argv[1])) if len(sys.argv) == 2 else []
    warning_penalty = sum(points for _, points in warnings)
    base_score = sum(points for _, _, points in scores)
    final_score = max(0, base_score - warning_penalty)

    summary = Path(os.environ.get("GITHUB_STEP_SUMMARY", "/tmp/pr-gate-score.md"))
    with summary.open("a", encoding="utf-8") as out:
        out.write("# Meika PR Gate Quality Score\n\n")
        out.write(f"**Final score: {final_score}/{MAX_SCORE}**  \n")
        out.write(f"**Base check score: {base_score}/{MAX_SCORE}**  \n")
        out.write(f"**Warning penalty: -{warning_penalty} points**  \n")
        out.write(f"**Detected warning events: {len(warnings)}**\n\n")
        out.write("| # | Check | Outcome | Score |\n|---:|---|---|---:|\n")
        for index, (label, outcome, points) in enumerate(scores, 1):
            out.write(f"| {index} | {label} | {outcome} | {points}/100 |\n")
        out.write("\n## Warning deductions\n\n")
        if warnings:
            for line, penalty in warnings:
                safe_line = line.replace("|", "\\|")
                out.write(f"- **-{penalty} points:** {safe_line[:500]}\n")
        else:
            out.write("No log archive supplied to this same-run scoring job; pytest warnings are fatal and scanner findings are enforced by their steps. Runner-level log warnings are not scored here.\n")
        out.write("\n## Scoring rules\n\n")
        out.write("- A required check earns 100 only when its GitHub Actions outcome is success.\n")
        out.write("- Failed, cancelled, missing, or skipped required checks earn 0.\n")
        out.write("- GitHub warning annotations cost 15 points each; Python/runtime warnings cost 10; standard tool warnings cost 5.\n")
        out.write("- Negative-test database errors are not counted as warnings; the corresponding test must still pass.\n")
        out.write("- This same-run score does not claim a full raw-log warning audit. Pytest uses warnings-as-errors; scanner findings are enforced by their steps. A post-run log audit must run after workflow completion to score runner/tool log warnings.\n")

    print(f"PR gate score: {final_score}/{MAX_SCORE} (base {base_score}; warning penalty {warning_penalty})")
    print(f"Warning events parsed from log archive: {len(warnings)}" if len(sys.argv) == 2 else "Warning log audit: not available during this workflow run; pytest warnings are errors.")
    for label, outcome, points in scores:
        print(f"{points:3d}/100  {label}: {outcome}")
    if final_score != MAX_SCORE or any(points != 100 for _, _, points in scores):
        print("::error::PR gate quality score is below 100% or warning events remain.")
        return 1
    print(f"All {len(CHECKS)} outcome checks scored 100/100. Total {MAX_SCORE}/{MAX_SCORE}. This is not a full raw-log warning audit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
