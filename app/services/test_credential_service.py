from unittest.mock import MagicMock, patch

from app.services.credential_service import CredentialService


def test_create_password_credential():
    db = MagicMock()

    with patch(
        "app.services.credential_service.hash_password",
        return_value="hashed-secret",
    ):
        credential = CredentialService.create_password_credential(
            db=db,
            user_id=123,
            password="password123",
        )

    assert credential.user_id == 123
    assert credential.type == "password"
    assert credential.secret_ref == "hashed-secret"
    assert credential.status == "active"

    db.add.assert_called_once()
    db.commit.assert_called_once()
    db.refresh.assert_called_once()


def test_verify_password_success():
    db = MagicMock()

    credential = MagicMock()
    credential.secret_ref = "stored-hash"

    db.query.return_value.filter.return_value.first.return_value = credential

    with patch(
        "app.services.credential_service.verify_password",
        return_value=True,
    ):
        result = CredentialService.verify_password_credential(
            db=db,
            user_id=1,
            password="correct",
        )

    assert result is True
    assert credential.last_used_at is not None
    db.commit.assert_called_once()


def test_verify_password_failure():
    db = MagicMock()

    credential = MagicMock()
    credential.secret_ref = "stored-hash"

    db.query.return_value.filter.return_value.first.return_value = credential

    with patch(
        "app.services.credential_service.verify_password",
        return_value=False,
    ):
        result = CredentialService.verify_password_credential(
            db=db,
            user_id=1,
            password="wrong",
        )

    assert result is False


def test_verify_password_missing_credential():
    db = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = None

    result = CredentialService.verify_password_credential(
        db=db,
        user_id=1,
        password="anything",
    )

    assert result is False
    