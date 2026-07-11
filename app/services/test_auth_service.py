from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from app.services.auth_service import AuthService


def test_register_user_success():
    db = MagicMock()

    fake_user = MagicMock()
    fake_user.id = 100

    with patch(
        "app.services.auth_service.User",
        return_value=fake_user,
    ):
        with patch(
            "app.services.auth_service.CredentialService.create_password_credential"
        ):
            user = AuthService.register_user(
                db=db,
                email="user@test.com",
                password="secret",
                display_name="User",
            )

    assert user == fake_user

    db.add.assert_called()
    db.flush.assert_called_once()
    db.commit.assert_called_once()
    db.refresh.assert_called_once()


def test_register_user_duplicate():
    db = MagicMock()

    db.flush.side_effect = IntegrityError(
        statement=None,
        params=None,
        orig=None,
    )

    with pytest.raises(HTTPException) as exc:
        AuthService.register_user(
            db=db,
            email="dup@test.com",
            password="secret",
        )

    assert exc.value.status_code == 409
    db.rollback.assert_called_once()


def test_login_user_missing_user():
    db = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = None

    result = AuthService.login_user(
        db=db,
        email="missing@test.com",
        password="pw",
    )

    assert result is None


def test_login_user_invalid_password():
    db = MagicMock()

    user = MagicMock()
    user.id = 1

    db.query.return_value.filter.return_value.first.return_value = user

    with patch(
        "app.services.auth_service.CredentialService.verify_password_credential",
        return_value=False,
    ):
        result = AuthService.login_user(
            db=db,
            email="user@test.com",
            password="bad",
        )

    assert result is None


def test_login_user_success():
    db = MagicMock()

    user = MagicMock()
    user.id = 55

    db.query.return_value.filter.return_value.first.return_value = user

    with patch(
        "app.services.auth_service.CredentialService.verify_password_credential",
        return_value=True,
    ):
        session = AuthService.login_user(
            db=db,
            email="user@test.com",
            password="secret",
        )

    assert session.user_id == 55

    db.add.assert_called()
    db.commit.assert_called()
    db.refresh.assert_called()


def test_audit_adds_record():
    db = MagicMock()

    AuthService._audit(
        db=db,
        actor_type="user",
        actor_id=1,
        action="login",
        resource="session",
    )

    db.add.assert_called_once()
    
def test_get_user_by_email_found():
    db = MagicMock()

    user = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = user

    result = AuthService.get_user_by_email(
        db=db,
        email="user@test.com",
    )

    assert result is user

    db.query.assert_called_once()


def test_get_user_found():
    db = MagicMock()

    user = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = user

    result = AuthService.get_user(
        db=db,
        user_id=123,
    )

    assert result is user

    db.query.assert_called_once()
    
def test_get_user_by_email_not_found():
    db = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = None

    result = AuthService.get_user_by_email(
        db=db,
        email="missing@test.com",
    )

    assert result is None


def test_get_user_not_found():
    db = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = None

    result = AuthService.get_user(
        db=db,
        user_id=999,
    )

    assert result is None
    