import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("check_codeql_sarif.py")


def make_sarif(severity=7.5, level="warning", extension=False):
    rule = {
        "id": "py/test-security-rule",
        "properties": {"security-severity": str(severity)},
    }

    driver = {"name": "CodeQL", "rules": []}
    tool = {"driver": driver}

    if extension:
        tool["extensions"] = [{"name": "Python", "rules": [rule]}]
    else:
        driver["rules"] = [rule]

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": tool,
            "results": [{
                "ruleId": "py/test-security-rule",
                "level": level,
                "message": {"text": "Test finding"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app/example.py"},
                        "region": {"startLine": 42},
                    }
                }],
            }],
        }],
    }


def run_checker(path):
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


def write_report(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def test_high_severity_driver_rule_fails(tmp_path):
    report = tmp_path / "driver.sarif"
    write_report(report, make_sarif(severity=7.5))

    result = run_checker(report)

    assert result.returncode == 1
    assert "py/test-security-rule" in result.stdout


def test_high_severity_extension_rule_fails(tmp_path):
    report = tmp_path / "extension.sarif"
    write_report(report, make_sarif(severity=7.5, extension=True))

    result = run_checker(report)

    assert result.returncode == 1
    assert "py/test-security-rule" in result.stdout


def test_low_severity_rule_passes(tmp_path):
    report = tmp_path / "low.sarif"
    write_report(report, make_sarif(severity=6.9))

    result = run_checker(report)

    assert result.returncode == 0


def test_error_level_finding_fails(tmp_path):
    report = tmp_path / "error.sarif"
    write_report(report, make_sarif(severity=2.0, level="error"))

    result = run_checker(report)

    assert result.returncode == 1


def test_multiple_reports_are_checked(tmp_path):
    write_report(
        tmp_path / "python.sarif",
        make_sarif(severity=3.0),
    )
    write_report(
        tmp_path / "security.sarif",
        make_sarif(severity=8.0),
    )

    result = run_checker(tmp_path)

    assert result.returncode == 1
    assert "SARIF reports: 2" in result.stdout


def test_empty_directory_fails(tmp_path):
    result = run_checker(tmp_path)

    assert result.returncode == 1
    assert "No SARIF reports found" in result.stdout


def test_missing_path_fails(tmp_path):
    result = run_checker(tmp_path / "missing")

    assert result.returncode == 1


def test_invalid_json_fails(tmp_path):
    report = tmp_path / "invalid.sarif"
    report.write_text("{invalid json", encoding="utf-8")

    result = run_checker(report)

    assert result.returncode == 1
    assert "Unable to parse" in result.stdout


def test_empty_report_fails(tmp_path):
    report = tmp_path / "empty.sarif"
    report.write_text("", encoding="utf-8")

    result = run_checker(report)

    assert result.returncode == 1
    assert "empty" in result.stdout

def test_non_security_rule_without_severity_passes(tmp_path):
    report = tmp_path / "summary.sarif"
    data = make_sarif()
    data["runs"][0]["tool"]["driver"]["rules"][0]["properties"] = {
        "tags": ["summary"]
    }
    write_report(report, data)

    result = run_checker(report)

    assert result.returncode == 0


def test_security_rule_without_severity_fails_closed(tmp_path):
    report = tmp_path / "missing-security-severity.sarif"
    data = make_sarif()
    data["runs"][0]["tool"]["driver"]["rules"][0]["properties"] = {
        "tags": ["security"]
    }
    write_report(report, data)

    result = run_checker(report)

    assert result.returncode == 1
    assert "missing security-severity metadata" in result.stdout
