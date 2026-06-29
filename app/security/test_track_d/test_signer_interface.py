import pytest

from app.security.track_d.signing.signer_interface import ISigner


class DummySigner(ISigner):
    pass


def test_sign_not_implemented():
    with pytest.raises(NotImplementedError):
        ISigner.sign(object(), b"hello")


def test_algorithm_not_implemented():
    with pytest.raises(NotImplementedError):
        ISigner.algorithm(object())


def test_key_id_not_implemented():
    with pytest.raises(NotImplementedError):
        ISigner.key_id(object())


def test_public_key_hex_not_implemented():
    with pytest.raises(NotImplementedError):
        ISigner.public_key_hex(object())


def test_is_hardware_not_implemented():
    with pytest.raises(NotImplementedError):
        ISigner.is_hardware(object())


def test_dummy_signer_is_abstract():
    with pytest.raises(TypeError):
        DummySigner()