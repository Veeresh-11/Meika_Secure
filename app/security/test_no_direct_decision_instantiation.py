import pathlib

def test_no_direct_decision_instantiation():
    root = pathlib.Path("app/security")
    violations = []

    allowed = {
        "decision.py",
        "pipeline.py",
        "adapter.py",
    }

    for file in root.rglob("*.py"):

        # Skip test files entirely
        if "test_" in file.name:
            continue

        if file.name in allowed:
            continue

        content = file.read_text()

        if "SecurityDecision(" in content:
            violations.append(str(file))

    assert not violations, f"Direct SecurityDecision usage found: {violations}"
