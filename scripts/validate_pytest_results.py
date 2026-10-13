#!/usr/bin/env python3
"""Fail CI on any skip not explicitly approved by the repository.

The only currently approved skips are legacy WebAuthn test modules that are
superseded by app/api/test_auth.py. Exact per-module counts and the reason are
intentional tripwires: a new skip, removed skip, or changed reason requires an
explicit review and update to this policy.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

EXPECTED = {
    "app.api.test_auth_webauthn": 5,
    "app.api.test_auth_webauthn_finish": 7,
}
EXPECTED_REASON = (
    "Superseded by app/api/test_auth.py after Production WebAuthn persistence migration."
)


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

    skipped: list[tuple[str, str, str]] = []
    unexpected: list[str] = []
    for case in cases:
        node = case.find("skipped")
        if node is None:
            continue
        classname = case.attrib.get("classname", "")
        name = case.attrib.get("name", "<unnamed>")
        reason = (node.attrib.get("message") or node.text or "").strip()
        if reason.startswith("Skipped: "):
            reason = reason[len("Skipped: "):]
        skipped.append((classname, name, reason))
        if classname not in EXPECTED:
            unexpected.append(f"{classname}::{name}: skip not allowlisted")
        elif reason != EXPECTED_REASON:
            unexpected.append(
                f"{classname}::{name}: unexpected skip reason {reason!r}"
            )

    actual = Counter(classname for classname, _, _ in skipped)
    for module, expected_count in EXPECTED.items():
        if actual[module] != expected_count:
            unexpected.append(
                f"{module}: expected exactly {expected_count} approved skips, "
                f"observed {actual[module]}"
            )

    unexpected_modules = set(actual) - set(EXPECTED)
    if unexpected_modules:
        unexpected.append(f"unapproved skipped modules: {sorted(unexpected_modules)}")

    print(f"Pytest cases reported: {len(cases)}")
    print(f"Skipped cases reported: {len(skipped)}")
    for module, count in sorted(actual.items()):
        print(f"  {module}: {count}")
    if unexpected:
        print("FAIL: unexpected or changed skips detected:")
        for item in unexpected:
            print(f" - {item}")
        return 1

    expected_total = sum(EXPECTED.values())
    if len(skipped) != expected_total:
        print(
            f"FAIL: expected exactly {expected_total} explicitly approved skips; "
            f"observed {len(skipped)}"
        )
        return 1

    print("PASS: all skips match the exact reviewed allowlist; no unexpected skips.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
