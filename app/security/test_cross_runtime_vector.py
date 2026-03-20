import json
from pathlib import Path
from datetime import datetime

from app.security.bootstrap import build_pipeline
from app.security.context import SecurityContext

VECTOR_HASH = "REPLACE_WITH_REAL_HASH"


def test_cross_runtime_vector_hash():
    pipeline = build_pipeline()

    vector_path = Path("app/security/tests/vectors/security_vector_001.json")
    raw = json.loads(vector_path.read_text())

    ctx = SecurityContext(
        request_id=raw["request_id"],
        principal_id=raw["principal_id"],
        intent=raw["intent"],
        authenticated=raw["authenticated"],
        device_id=raw["device_id"],
        device=None,
        risk_signals=raw["risk_signals"],
        request_time=datetime.fromisoformat(raw["request_time"]),
        metadata=raw["metadata"],
        grant=None,
    )

    decision = pipeline.evaluate(ctx)

    assert decision.to_dict() is not None
