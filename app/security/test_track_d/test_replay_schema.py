import json
from jsonschema import validate

from app.security.track_d.schemas import (
    replay_verification_result_schema
)


def test_replay_verification_schema_valid():
    payload = {
        "valid": True,
        "status": "CHAIN_VALID",
        "details": {}
    }

    validate(instance=payload, schema=replay_verification_result_schema)


def test_replay_verification_schema_rejects_extra_fields():
    payload = {
        "valid": True,
        "status": "CHAIN_VALID",
        "details": {},
        "extra": "forbidden"
    }

    try:
        validate(instance=payload, schema=replay_verification_result_schema)
        assert False, "Schema accepted forbidden field"
    except Exception:
        assert True
