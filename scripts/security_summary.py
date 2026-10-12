"""Aggregate deep-scan findings and fail closed on unresolved findings.

This is a CI release gate, not a replacement for reviewing the individual reports.
Missing or malformed reports are treated as scanner failures, not as clean results.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


def load_json(path: str) -> Any:
    file_path = Path(path)
    if not file_path.is_file() or file_path.stat().st_size == 0:
        raise RuntimeError(f"Required security report missing or empty: {path}")
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to parse security report {path}: {exc}") from exc


def load_jsonl(path: str) -> list[dict[str, Any]]:
    file_path = Path(path)
    if not file_path.is_file() or file_path.stat().st_size == 0:
        raise RuntimeError(f"Required security report missing or empty: {path}")
    findings: list[dict[str, Any]] = []
    for number, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSONL in {path}:{number}: {exc}") from exc
        if isinstance(value, dict):
            findings.append(value)
        elif isinstance(value, list):
            findings.extend(item for item in value if isinstance(item, dict))
        else:
            raise RuntimeError(f"Unexpected JSONL value in {path}:{number}")
    return findings


def require_step_summary() -> str:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        raise RuntimeError("GITHUB_STEP_SUMMARY is not set")
    return path


def main() -> int:
    counts: dict[str, int] = {}
    blockers: list[str] = []

    # A report alone is not enough: scanners must also exit successfully.
    scanner_outcomes = {
        "OWASP ZAP": "ZAP_OUTCOME",
        "Nuclei": "NUCLEI_OUTCOME",
        "Schemathesis": "SCHEMATHESIS_OUTCOME",
        "pip-audit": "PIP_AUDIT_OUTCOME",
        "OSV-Scanner": "OSV_OUTCOME",
        "Bandit": "BANDIT_OUTCOME",
        "Trivy config": "TRIVY_CONFIG_OUTCOME",
    }
    for scanner, variable in scanner_outcomes.items():
        outcome = os.environ.get(variable, "missing")
        if outcome != "success":
            blockers.append(f"{scanner} did not complete successfully (outcome={outcome})")

    zap = load_json("zap-report.json")
    sites = zap.get("site")
    if not isinstance(sites, list):
        raise RuntimeError("ZAP report has no valid 'site' array")
    zap_alerts = [
        alert
        for site in sites
        if isinstance(site, dict)
        for alert in site.get("alerts", [])
        if isinstance(alert, dict)
    ]
    zap_high = [
        item for item in zap_alerts
        if str(item.get("riskdesc", "")).lower().startswith("high")
    ]
    zap_medium = [
        item for item in zap_alerts
        if str(item.get("riskdesc", "")).lower().startswith("medium")
    ]
    counts["ZAP high"] = len(zap_high)
    counts["ZAP medium"] = len(zap_medium)
    if zap_high:
        blockers.append(f"ZAP high-risk alerts: {len(zap_high)}")
    if zap_medium:
        blockers.append(f"ZAP medium-risk alerts: {len(zap_medium)}")

    nuclei = load_jsonl("nuclei.jsonl")
    nuclei_critical_high = [
        item for item in nuclei
        if str(item.get("info", {}).get("severity", "")).lower()
        in {"critical", "high"}
    ]
    counts["Nuclei critical/high"] = len(nuclei_critical_high)
    if nuclei_critical_high:
        blockers.append(f"Nuclei critical/high findings: {len(nuclei_critical_high)}")

    pip_audit = load_json("pip-audit-report.json")
    pip_vulnerabilities = [
        (dependency.get("name", "unknown"), vuln.get("id", "unknown"))
        for dependency in pip_audit.get("dependencies", [])
        if isinstance(dependency, dict)
        for vuln in dependency.get("vulns", [])
        if isinstance(vuln, dict)
    ]
    counts["pip-audit vulnerabilities"] = len(pip_vulnerabilities)
    if pip_vulnerabilities:
        blockers.append(f"pip-audit known vulnerabilities: {len(pip_vulnerabilities)}")

    osv = load_json("osv-report.json")
    osv_vulnerabilities = [
        (package.get("package", {}).get("name", "unknown"), vuln.get("id", "unknown"))
        for result in osv.get("results", [])
        if isinstance(result, dict)
        for package in result.get("packages", [])
        if isinstance(package, dict)
        for vuln in package.get("vulnerabilities", [])
        if isinstance(vuln, dict)
    ]
    counts["OSV vulnerabilities"] = len(osv_vulnerabilities)
    if osv_vulnerabilities:
        blockers.append(f"OSV known vulnerabilities: {len(osv_vulnerabilities)}")

    bandit = load_json("bandit-report.json")
    bandit_results = bandit.get("results")
    if not isinstance(bandit_results, list):
        raise RuntimeError("Bandit report has no valid 'results' array")
    bandit_medium_high = [
        item for item in bandit_results
        if str(item.get("issue_severity", "")).upper() in {"MEDIUM", "HIGH"}
    ]
    counts["Bandit medium/high"] = len(bandit_medium_high)
    if bandit_medium_high:
        blockers.append(f"Bandit medium/high findings: {len(bandit_medium_high)}")

    trivy_paths = ["trivy-config.sarif"]
    if Path("trivy-image.sarif").is_file():
        trivy_paths.append("trivy-image.sarif")
    trivy_total = 0
    for path in trivy_paths:
        sarif = load_json(path)
        runs = sarif.get("runs")
        if not isinstance(runs, list):
            raise RuntimeError(f"Trivy report has no valid 'runs' array: {path}")
        results = [
            result
            for run in runs
            if isinstance(run, dict)
            for result in run.get("results", [])
            if isinstance(result, dict)
        ]
        trivy_total += len(results)
        if results:
            blockers.append(f"{path} findings (configured HIGH/CRITICAL scan): {len(results)}")
    counts["Trivy high/critical findings"] = trivy_total

    schemathesis_path = Path("schemathesis-report.txt")
    if not schemathesis_path.is_file() or schemathesis_path.stat().st_size == 0:
        raise RuntimeError("Required Schemathesis report missing or empty")
    schemathesis = schemathesis_path.read_text(encoding="utf-8", errors="replace")
    # Count unique failing cases, not repeated mentions in the report.
    case_ids = set(re.findall(r"(?m)^\s*Test Case ID:\s*([A-Za-z0-9_-]+)", schemathesis))
    if case_ids:
        schema_failures = len(case_ids)
    else:
        final_summary = re.findall(r"(?m)^=+\s*(\d+)\s+failed\b", schemathesis)
        failed_cases = re.findall(r"(?im)^\s*FAILED\s+\S+", schemathesis)
        schema_failures = int(final_summary[-1]) if final_summary else len(set(failed_cases))
    counts["Schemathesis failures"] = schema_failures
    if schema_failures:
        blockers.append(f"Schemathesis test failures: {schema_failures}")

    summary_path = require_step_summary()
    with open(summary_path, "a", encoding="utf-8") as output:
        output.write("## Meika Deep Security Gate\n\n")
        for name, count in counts.items():
            output.write(f"- {name}: **{count}**\n")
        output.write("\n")
        if blockers:
            output.write("### Blocking findings\n")
            for blocker in blockers:
                output.write(f"- {blocker}\n")
        else:
            output.write("No blocking findings were reported by the required scanners.\n")

    print("=== Deep security gate summary ===")
    for name, count in counts.items():
        print(f"{name}: {count}")
    if blockers:
        print("BLOCKING FINDINGS:")
        for blocker in blockers:
            print(f"- {blocker}")
        return 1
    print("PASS: no blocking findings in required scanner reports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
