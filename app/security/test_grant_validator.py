from datetime import datetime, timedelta

import pytest

from app.security.context import SecurityContext
from app.security.errors import SecurityPipelineError
from app.security.grants.models import create_grant
from app.security.grants.store import GrantStore
from app.security.grants.validator import GrantValidator
from app.security.grants.store import GrantNotFoundError

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
        
def test_validate_missing_grant():

    class MissingStore:
        def get(self, grant_id):
            raise GrantNotFoundError(grant_id)

    validator = GrantValidator(MissingStore())

    with pytest.raises(SecurityPipelineError):
        validator.validate(
            "missing",
            SecurityContext.fake_allow_context(),
        )


def test_validate_expired_grant():

    class ExpiredGrant:
        principal_id = "user"
        intent = "authentication.attempt"
        expires_at = datetime.utcnow() - timedelta(minutes=1)

    class Store:
        def get(self, grant_id):
            return ExpiredGrant()

    validator = GrantValidator(Store())

    ctx = SecurityContext.fake_allow_context()

    with pytest.raises(SecurityPipelineError):
        validator.validate(
            "grant1",
            ctx,
        )