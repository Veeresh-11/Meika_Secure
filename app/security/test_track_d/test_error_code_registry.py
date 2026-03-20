import pytest

from app.security.track_d.error_codes import (
    ERROR_CODES,
    ErrorClass,
    ErrorStage,
    ErrorDefinition,
    get_error_definition,
)


def test_registry_is_not_empty():
    assert len(ERROR_CODES) > 0


def test_all_entries_are_error_definitions():
    for code, definition in ERROR_CODES.items():
        assert isinstance(definition, ErrorDefinition)
        assert definition.code == code


def test_error_classes_are_valid():
    for definition in ERROR_CODES.values():
        assert isinstance(definition.error_class, ErrorClass)


def test_error_stages_are_valid():
    for definition in ERROR_CODES.values():
        assert isinstance(definition.stage, ErrorStage)


def test_error_codes_are_unique():
    codes = [d.code for d in ERROR_CODES.values()]
    assert len(codes) == len(set(codes))


def test_registry_is_closed():
    with pytest.raises(KeyError):
        get_error_definition("MEIKA_UNKNOWN_ERROR")


def test_error_codes_are_stable_strings():
    for definition in ERROR_CODES.values():
        assert definition.code.startswith("MEIKA_")
        assert definition.code.isupper()


def test_no_runtime_logic_leakage():
    """
    Registry must be pure data + lookup only.

    We forbid runtime imports, not English words.
    """
    forbidden_imports = [
        "import time",
        "from time",
        "import random",
        "from random",
        "import logging",
        "from logging",
    ]

    source = open(
        "app/security/track_d/error_codes.py", "r", encoding="utf-8"
    ).read()

    for token in forbidden_imports:
        assert token not in source

