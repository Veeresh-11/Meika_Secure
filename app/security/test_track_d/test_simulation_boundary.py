from jsonschema import validate

from app.security.track_d.schemas import simulation_result_schema


def test_simulation_is_non_authoritative():
    payload = {
        "simulated_outcome": "WARN",
        "simulated_reason": "Policy would deny",
        "authoritative": False,
        "warnings": {}
    }

    validate(instance=payload, schema=simulation_result_schema)


def test_simulation_cannot_be_authoritative():
    payload = {
        "simulated_outcome": "ALLOW",
        "simulated_reason": "Test",
        "authoritative": True,
        "warnings": {}
    }

    try:
        validate(instance=payload, schema=simulation_result_schema)
        assert False
    except Exception:
        assert True
