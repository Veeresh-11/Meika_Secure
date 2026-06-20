from datetime import datetime

import pytest

from app.security.context import SecurityContext
from app.security.errors import SecurityPipelineError
from app.security.grants.models import create_grant
from app.security.grants.store import GrantStore
from app.security.grants.validator import GrantValidator


def make_context():
    return SecurityContext(
        request_id="req1",
        principal_id="user1",
        intent="authentication.attempt",
        authenticated=True,
        device_id=None,
        device=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )


def test_validate_success():
    store = GrantStore()

    grant = create_grant(
        principal_id="user1",
        intent="authentication.attempt",
        lifetime_seconds=300,
        issued_by_policy="v1",
        justification="test",
    )

    store.add(grant)

    validator = GrantValidator(store)

    assert (
        validator.validate(
            grant.grant_id,
            make_context(),
        )
        is None
    )


def test_missing_grant_id():
    validator = GrantValidator(GrantStore())

    with pytest.raises(SecurityPipelineError):
        validator.validate("", make_context())


def test_wrong_principal():
    store = GrantStore()

    grant = create_grant(
        principal_id="another-user",
        intent="authentication.attempt",
        lifetime_seconds=300,
        issued_by_policy="v1",
        justification="test",
    )

    store.add(grant)

    validator = GrantValidator(store)

    with pytest.raises(SecurityPipelineError):
        validator.validate(
            grant.grant_id,
            make_context(),
        )


def test_wrong_intent():
    store = GrantStore()

    grant = create_grant(
        principal_id="user1",
        intent="admin.action",
        lifetime_seconds=300,
        issued_by_policy="v1",
        justification="test",
    )

    store.add(grant)

    validator = GrantValidator(store)

    with pytest.raises(SecurityPipelineError):
        validator.validate(
            grant.grant_id,
            make_context(),
        )