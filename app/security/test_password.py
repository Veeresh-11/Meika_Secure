import pytest

from app.security.password import (
    hash_password,
    verify_password,
)


def test_hash_password_returns_hash():
    password = "SuperSecurePassword123!"

    hashed = hash_password(password)

    assert hashed != password
    assert isinstance(hashed, str)
    assert len(hashed) > 20


def test_verify_password_success():
    password = "SuperSecurePassword123!"

    hashed = hash_password(password)

    assert verify_password(
        hashed,
        password,
    ) is True


def test_verify_password_failure():
    password = "SuperSecurePassword123!"

    hashed = hash_password(password)

    assert verify_password(
        hashed,
        "WrongPassword",
    ) is False