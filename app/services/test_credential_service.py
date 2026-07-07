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
    
def test_create_webauthn_credential():

    db = MagicMock()

    credential = CredentialService.create_webauthn_credential(
        db=db,
        user_id=123,
        credential_id="credential-123",
        public_key="public-key",
        device_id="device-456",
        hardware_backed=True,
        attestation_verified=True,
        attestation_type="basic",
    )

    assert credential.user_id == 123
    assert credential.credential_id == "credential-123"
    assert credential.public_key == "public-key"
    assert credential.device_id == "device-456"
    assert credential.hardware_backed is True
    assert credential.attestation_verified is True
    assert credential.attestation_type == "basic"

    db.add.assert_called_once()
    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_get_webauthn_credential():

    db = MagicMock()

    credential = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = credential

    result = CredentialService.get_webauthn_credential(
        db=db,
        credential_id="credential-123",
    )

    assert result == credential
    
def test_update_sign_count():

    db = MagicMock()

    credential = MagicMock()
    credential.sign_count = 0

    CredentialService.update_sign_count(
        db=db,
        credential=credential,
        sign_count=42,
    )

    assert credential.sign_count == 42

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_touch_last_used():

    db = MagicMock()

    credential = MagicMock()

    credential.last_used_at = None

    CredentialService.touch_last_used(
        db=db,
        credential=credential,
    )

    assert credential.last_used_at is not None

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_revoke_webauthn_credential():

    db = MagicMock()

    credential = MagicMock()

    credential.revoked = False

    CredentialService.revoke_webauthn_credential(
        db=db,
        credential=credential,
    )

    assert credential.revoked is True

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_get_webauthn_credential_not_found():

    db = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = None

    result = CredentialService.get_webauthn_credential(
        db=db,
        credential_id="missing",
    )

    assert result is None
    
def test_get_webauthn_credential_revoked():

    db = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = None

    result = CredentialService.get_webauthn_credential(
        db=db,
        credential_id="revoked",
    )

    assert result is None