# app/api/test_health_full.py

from app.api.health import health


def test_health():
    assert health() == {"status": "ok"}