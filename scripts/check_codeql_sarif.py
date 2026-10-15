#!/usr/bin/env python3
"""Fail CI when CodeQL SARIF contains unresolved high/critical security findings."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

HIGH_THRESHOLD = 7.0


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: check_codeql_sarif.py <sarif-file>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    if not path.is_file() or path.stat().st_size == 0:
        print(f"::error::CodeQL SARIF report is missing or empty: {path}")
        return 1

    try:
        sarif: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error::Unable to parse CodeQL SARIF report: {exc}")
        return 1

    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        print("::error::CodeQL SARIF report has no valid runs.")
        return 1

    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[tuple[str, str, str, float]] = []
    for run in runs:
        if not isinstance(run, dict):
            print("::error::CodeQL SARIF contains a malformed run.")
            return 1
        tool = run.get("tool", {}).get("driver", {})
        rules = tool.get("rules", []) if isinstance(tool, dict) else []
        for rule in rules:
            if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                rules_by_id[rule["id"]] = rule

        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId", "unknown"))
            rule = rules_by_id.get(rule_id, {})
            properties = rule.get("properties", {}) if isinstance(rule, dict) else {}
            raw_severity = properties.get("security-severity", properties.get("securitySeverity"))
            try:
                severity = float(raw_severity)
            except (TypeError, ValueError):
                severity = 0.0
            level = str(result.get("level", "warning")).lower()
            message = result.get("message", {})
            text = str(message.get("text", "")) if isinstance(message, dict) else ""
            locations = result.get("locations", [])
            location = "unknown location"
            if locations and isinstance(locations[0], dict):
                physical = locations[0].get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
                region = physical.get("region", {}) if isinstance(physical, dict) else {}
                uri = artifact.get("uri", "unknown file") if isinstance(artifact, dict) else "unknown file"
                line = region.get("startLine") if isinstance(region, dict) else None
                location = f"{uri}:{line}" if line else str(uri)
            if severity >= HIGH_THRESHOLD or level == "error":
                results.append((rule_id, location, text, severity))

    print(f"CodeQL runs: {len(runs)}")
    print(f"High/critical or error-level findings: {len(results)}")
    for rule_id, location, message, severity in results:
        print(f"::error file={location}::CodeQL {rule_id} (security-severity={severity}): {message[:500]}")

    if results:
        print("::error::Resolve high/critical CodeQL findings before merging.")
        return 1
    print("PASS: no high/critical or error-level CodeQL findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
