import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

SCRIPTS_DIR = str(Path(__file__).resolve().parents[1] / "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import validate_schema as validator


def test_schema_metadata_accepts_canonical_values():
    cursor = Mock()
    cursor.fetchall.return_value = [
        (
            1,
            validator.EXPECTED_SCHEMA_VERSION,
            validator.EXPECTED_SCHEMA_CHECKSUM,
        )
    ]

    validator.validate_schema_metadata(cursor)


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [(2, validator.EXPECTED_SCHEMA_VERSION,
          validator.EXPECTED_SCHEMA_CHECKSUM)],
        [
            (1, validator.EXPECTED_SCHEMA_VERSION,
             validator.EXPECTED_SCHEMA_CHECKSUM),
            (2, validator.EXPECTED_SCHEMA_VERSION,
             validator.EXPECTED_SCHEMA_CHECKSUM),
        ],
    ],
)
def test_schema_metadata_rejects_missing_or_unexpected_rows(rows):
    cursor = Mock()
    cursor.fetchall.return_value = rows

    with pytest.raises(RuntimeError, match="exactly one row"):
        validator.validate_schema_metadata(cursor)


def test_schema_metadata_rejects_wrong_version():
    cursor = Mock()
    cursor.fetchall.return_value = [
        (1, "999.0.0", validator.EXPECTED_SCHEMA_CHECKSUM)
    ]

    with pytest.raises(RuntimeError, match="version mismatch"):
        validator.validate_schema_metadata(cursor)


def test_schema_metadata_rejects_wrong_checksum():
    cursor = Mock()
    cursor.fetchall.return_value = [
        (1, validator.EXPECTED_SCHEMA_VERSION, "0" * 64)
    ]

    with pytest.raises(RuntimeError, match="checksum mismatch"):
        validator.validate_schema_metadata(cursor)


def test_schema_metadata_trigger_accepts_enabled_trigger():
    cursor = Mock()
    cursor.fetchone.return_value = (True,)

    validator.validate_schema_metadata_trigger(cursor)


@pytest.mark.parametrize("result", [None, (False,)])
def test_schema_metadata_trigger_rejects_missing_or_disabled_trigger(result):
    cursor = Mock()
    cursor.fetchone.return_value = result

    with pytest.raises(RuntimeError, match="immutability trigger"):
        validator.validate_schema_metadata_trigger(cursor)
