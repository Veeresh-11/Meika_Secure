# app/security/test_evidence_writer_full.py

import pytest
from unittest.mock import Mock, patch

from app.security.evidence.writer import (
    EvidenceWriter,
)
from app.security.errors import SecurityInvariantViolation


@patch("app.security.evidence.writer.build_evidence_record")
def test_write_decision_success(mock_build):
    store = Mock()

    record = Mock()
    mock_build.return_value = record

    store.append.return_value = "hash123"

    writer = EvidenceWriter(store)

    result = writer.write_decision(
        context=Mock(),
        decision=Mock(),
    )

    assert result == "hash123"


@patch("app.security.evidence.writer.build_evidence_record")
def test_write_decision_commit_failure(mock_build):
    store = Mock()

    record = Mock()
    mock_build.return_value = record

    store.append.return_value = None

    writer = EvidenceWriter(store)

    with pytest.raises(SecurityInvariantViolation):
        writer.write_decision(
            context=Mock(),
            decision=Mock(),
        )