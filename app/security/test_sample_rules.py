from datetime import datetime, timedelta
from types import SimpleNamespace

from app.security.simulation.sample_rules import (
    warn_grant_near_expiry,
)


def test_no_grant_returns_none():

    ctx = SimpleNamespace(
        grant=None,
        request_time=datetime.utcnow(),
    )

    assert warn_grant_near_expiry(ctx, None) is None


def test_grant_not_near_expiry_returns_none():

    now = datetime.utcnow()

    grant = SimpleNamespace(
        expires_at=now + timedelta(minutes=10)
    )

    ctx = SimpleNamespace(
        grant=grant,
        request_time=now,
    )

    assert warn_grant_near_expiry(ctx, None) is None


def test_grant_near_expiry_returns_warning():

    now = datetime.utcnow()

    grant = SimpleNamespace(
        expires_at=now + timedelta(seconds=120)
    )

    ctx = SimpleNamespace(
        grant=grant,
        request_time=now,
    )

    result = warn_grant_near_expiry(ctx, None)

    assert result.rule_id == "grant.near.expiry"
    assert result.severity == "WARN"