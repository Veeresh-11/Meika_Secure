#!/usr/bin/env python3
"""Fail CI when CodeQL SARIF contains high-severity security findings."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

HIGH_THRESHOLD = 7.0


class SarifError(Exception):
    """Raised when a SARIF report is missing or malformed."""


def load_reports(path: Path) -> list[tuple[Path, dict[str, Any]]]:
    if path.is_dir():
        files = sorted(path.glob("*.sarif"))
    elif path.is_file():
        files = [path]
    else:
        raise SarifError(f"SARIF path does not exist: {path}")

    if not files:
        raise SarifError(f"No SARIF reports found: {path}")

    reports = []

    for report_path in files:
        if report_path.stat().st_size == 0:
            raise SarifError(f"SARIF report is empty: {report_path}")

        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SarifError(
                f"Unable to parse {report_path}: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise SarifError(f"SARIF root must be an object: {report_path}")

        runs = data.get("runs")
        if not isinstance(runs, list) or not runs:
            raise SarifError(
                f"SARIF report has no valid runs: {report_path}"
            )

        reports.append((report_path, data))

    return reports


def collect_rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tool = run.get("tool")
    if not isinstance(tool, dict):
        raise SarifError("SARIF run has no valid tool object")

    components = []

    driver = tool.get("driver")
    if not isinstance(driver, dict):
        raise SarifError("SARIF run has no valid tool.driver")

    components.append(driver)

    extensions = tool.get("extensions", [])
    if not isinstance(extensions, list):
        raise SarifError("SARIF tool.extensions must be a list")

    for extension in extensions:
        if not isinstance(extension, dict):
            raise SarifError("Malformed SARIF tool extension")
        components.append(extension)

    rules_by_id = {}

    for component in components:
        rules = component.get("rules", [])
        if not isinstance(rules, list):
            raise SarifError("SARIF rule collection must be a list")

        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                raise SarifError("Malformed SARIF rule descriptor")

            rules_by_id[rule["id"]] = rule

    return rules_by_id


def get_severity(rule: dict[str, Any], rule_id: str) -> float:
    properties = rule.get("properties", {})
    if not isinstance(properties, dict):
        raise SarifError(f"Malformed properties for rule {rule_id}")

    raw = properties.get(
        "security-severity",
        properties.get("securitySeverity"),
    )

    if raw is None:
        tags = properties.get("tags", [])
        if not isinstance(tags, list) or not all(
            isinstance(tag, str) for tag in tags
        ):
            raise SarifError(f"Invalid tags for rule {rule_id}")

        if "security" in tags:
            raise SarifError(
                f"Security rule {rule_id} is missing security-severity metadata"
            )

        return 0.0

    try:
        severity = float(raw)
    except (TypeError, ValueError) as exc:
        raise SarifError(
            f"Invalid security severity for rule {rule_id}: {raw!r}"
        ) from exc

    if not math.isfinite(severity) or not 0.0 <= severity <= 10.0:
        raise SarifError(
            f"Out-of-range security severity for rule {rule_id}: {raw!r}"
        )

    return severity


def get_location(result: dict[str, Any]) -> str:
    locations = result.get("locations", [])

    if not isinstance(locations, list):
        raise SarifError("SARIF result locations must be a list")

    if not locations:
        return "unknown location"

    first = locations[0]
    if not isinstance(first, dict):
        raise SarifError("Malformed SARIF location")

    physical = first.get("physicalLocation", {})
    if not isinstance(physical, dict):
        raise SarifError("Malformed SARIF physical location")

    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})

    if not isinstance(artifact, dict) or not isinstance(region, dict):
        raise SarifError("Malformed SARIF artifact location or region")

    uri = artifact.get("uri", "unknown file")
    line = region.get("startLine")

    return f"{uri}:{line}" if line else str(uri)


def inspect_report(data: dict[str, Any]) -> tuple[int, list[tuple]]:
    findings = []
    runs = data["runs"]

    for run in runs:
        if not isinstance(run, dict):
            raise SarifError("SARIF contains a malformed run")

        rules = collect_rules(run)
        results = run.get("results", [])

        if not isinstance(results, list):
            raise SarifError("SARIF run results must be a list")

        for result in results:
            if not isinstance(result, dict):
                raise SarifError("SARIF contains a malformed result")

            rule_id = result.get("ruleId")
            if not isinstance(rule_id, str):
                raise SarifError("SARIF result has no valid ruleId")

            rule = rules.get(rule_id)
            if rule is None:
                raise SarifError(
                    f"No rule descriptor found for result: {rule_id}"
                )

            severity = get_severity(rule, rule_id)

            level = result.get("level", "warning")
            if not isinstance(level, str):
                raise SarifError(f"Invalid result level for {rule_id}")

            level = level.lower()

            message = result.get("message", {})
            if not isinstance(message, dict):
                raise SarifError(f"Malformed message for {rule_id}")

            text = message.get("text", "")
            if not isinstance(text, str):
                raise SarifError(f"Malformed message text for {rule_id}")

            location = get_location(result)

            if severity >= HIGH_THRESHOLD or level == "error":
                findings.append(
                    (rule_id, location, text, severity, level)
                )

    return len(runs), findings


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "Usage: check_codeql_sarif.py <sarif-file-or-directory>",
            file=sys.stderr,
        )
        return 2

    try:
        reports = load_reports(Path(sys.argv[1]))

        total_runs = 0
        all_findings = []

        for report_path, report in reports:
            runs, findings = inspect_report(report)
            total_runs += runs
            all_findings.extend(
                (report_path, *finding) for finding in findings
            )

    except SarifError as exc:
        print(f"::error::{exc}")
        return 1

    print(f"SARIF reports: {len(reports)}")
    print(f"CodeQL runs: {total_runs}")
    print(f"High/critical or error-level findings: {len(all_findings)}")

    for report_path, rule_id, location, message, severity, level in all_findings:
        print(
            f"::error file={location}::"
            f"CodeQL {rule_id} "
            f"(security-severity={severity}, level={level}, "
            f"report={report_path}): {message[:500]}"
        )

    if all_findings:
        print("::error::Resolve high/critical CodeQL findings before merging.")
        return 1

    print("PASS: no high/critical or error-level CodeQL findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
