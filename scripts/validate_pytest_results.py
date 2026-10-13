#!/usr/bin/env python3
"""Fail CI unless the complete collected pytest suite reports zero skips."""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: validate_pytest_results.py <junit-xml>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    if not path.is_file() or path.stat().st_size == 0:
        print(f"FAIL: required pytest JUnit report missing or empty: {path}")
        return 1

    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        print(f"FAIL: unable to parse pytest JUnit report: {exc}")
        return 1

    cases = list(root.iter("testcase"))
    if not cases:
        print("FAIL: pytest reported zero test cases")
        return 1

    skipped = []
    failures = []
    for case in cases:
        classname = case.attrib.get("classname", "")
        name = case.attrib.get("name", "<unnamed>")
        node = case.find("skipped")
        if node is not None:
            reason = (node.attrib.get("message") or node.text or "").strip()
            skipped.append((classname, name, reason))
        if case.find("failure") is not None or case.find("error") is not None:
            failures.append(f"{classname}::{name}")

    print(f"Pytest cases reported: {len(cases)}")
    print(f"Skipped cases reported: {len(skipped)}")
    print(f"Failed/error cases reported in JUnit: {len(failures)}")
    if skipped:
        print("FAIL: no skipped tests are permitted in the required suite:")
        for classname, name, reason in skipped:
            print(f" - {classname}::{name}: {reason}")
    if failures:
        print("FAIL: JUnit contains failed/error cases:")
        for item in failures:
            print(f" - {item}")
    if skipped or failures:
        return 1

    print("PASS: all collected tests ran without skips, failures, or errors.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
