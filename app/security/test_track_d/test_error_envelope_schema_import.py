from app.security.track_d.schemas.error_envelope_schema import (
    error_envelope_schema,
)

def test_schema_exists():
    assert error_envelope_schema is not None

def test_schema_type():
    assert error_envelope_schema["type"] == "object"

def test_required_fields():
    assert "error_code" in error_envelope_schema["required"]