from jsonschema import validate

from app.security.track_d.schemas import error_envelope_schema


def test_error_envelope_schema_valid():
    payload = {
        "error_code": "MEIKA_DEVICE_CLONED",
        "error_class": "DEVICE",
        "human_message": "Device integrity failed",
        "fingerprint": "a" * 64,
        "authoritative": True
    }

    validate(instance=payload, schema=error_envelope_schema)


def test_error_envelope_authoritative_flag_required():
    payload = {
        "error_code": "MEIKA_AUTH_UNAUTHENTICATED",
        "error_class": "AUTH",
        "human_message": "Unauthenticated",
        "fingerprint": "b" * 64
    }

    try:
        validate(instance=payload, schema=error_envelope_schema)
        assert False
    except Exception:
        assert True
