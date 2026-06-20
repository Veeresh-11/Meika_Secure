from datetime import datetime, timedelta

from app.security.grants.models import create_grant


def test_create_grant():
    grant = create_grant(
        principal_id="user1",
        intent="authentication.attempt",
        lifetime_seconds=300,
        issued_by_policy="v1",
        justification="test",
    )

    assert grant.principal_id == "user1"
    assert grant.intent == "authentication.attempt"
    assert grant.issued_by_policy == "v1"
    assert grant.justification == "test"


def test_grant_not_expired():
    grant = create_grant(
        principal_id="user1",
        intent="authentication.attempt",
        lifetime_seconds=300,
        issued_by_policy="v1",
        justification="test",
    )

    assert grant.is_expired() is False


def test_grant_expired():
    grant = create_grant(
        principal_id="user1",
        intent="authentication.attempt",
        lifetime_seconds=1,
        issued_by_policy="v1",
        justification="test",
    )

    future = datetime.utcnow() + timedelta(hours=1)

    assert grant.is_expired(future) is True


def test_to_dict():
    grant = create_grant(
        principal_id="user1",
        intent="authentication.attempt",
        lifetime_seconds=300,
        issued_by_policy="v1",
        justification="test",
    )

    data = grant.to_dict()

    assert data["principal_id"] == "user1"
    assert data["intent"] == "authentication.attempt"