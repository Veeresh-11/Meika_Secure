#!/usr/bin/env python3
"""Compare normalized Schemathesis outcomes for repeated runs on one commit."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def summarize(path: Path) -> dict[str, int | bool]:
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"Required Schemathesis report missing or empty: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")

    operations = re.search(r"Selected:\s*(\d+)\s*/\s*(\d+)", text)
    tested = re.search(r"Tested:\s*(\d+)", text)
    cases = re.search(r"Test cases:\s*(\d+)\s+generated,\s*(\d+)\s+passed", text)
    failed = re.search(r"(?im)^\s*(\d+)\s+failed\b", text)
    no_issues = "No issues found" in text

    if not operations or not tested or not cases:
        raise ValueError(f"Could not parse required Schemathesis metrics from {path}")
    failed_count = int(failed.group(1)) if failed else 0
    if not no_issues and failed_count == 0:
        raise ValueError(f"Report has no successful 'No issues found' marker or parseable failure count: {path}")

    return {
        "operations_selected": int(operations.group(1)),
        "operations_total": int(operations.group(2)),
        "operations_tested": int(tested.group(1)),
        "cases_generated": int(cases.group(1)),
        "cases_passed": int(cases.group(2)),
        "cases_failed": failed_count,
        "no_issues": no_issues,
    }


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        first = summarize(args.first)
        second = summarize(args.second)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Reproducibility validation failed: {exc}") from exc

    result = {
        "commit": args.commit,
        "seed": args.seed,
        "tool": "Schemathesis",
        "normalized_outcomes_match": first == second,
        "first": {"metrics": first, "sha256": sha256(args.first)},
        "second": {"metrics": second, "sha256": sha256(args.second)},
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))

    if first != second:
        raise SystemExit("Normalized Schemathesis outcomes differ for the same commit and seed.")
    if first["cases_failed"] or second["cases_failed"]:
        raise SystemExit("Schemathesis reported failing cases.")
    print("PASS: repeated Schemathesis runs produced identical normalized outcomes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
