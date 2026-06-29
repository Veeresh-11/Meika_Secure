from datetime import datetime
from unittest.mock import patch

import pytest

from app.security.decision import (
    DecisionOutcome,
    SecurityDecision,
    SecurityDecisionFactory,
)


def test_factory_create():

    decision = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.ALLOW,
        reason="ok",
        policy_version="v1",
        evaluated_at=datetime.utcnow(),
        obligations={"a": 1},
        evidence_hash="hash1",
    )

    assert decision.outcome == DecisionOutcome.ALLOW
    assert decision.evidence_hash == "hash1"


def test_to_dict():

    decision = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.DENY,
        reason="deny",
        policy_version="v1",
        evaluated_at=datetime.utcnow(),
        obligations={"x": 1},
        evidence_hash="hash2",
    )

    data = decision.to_dict()

    assert data["outcome"] == "deny"
    assert data["reason"] == "deny"
    assert data["evidence_hash"] == "hash2"


def test_to_dict_none_datetime():

    decision = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.ALLOW,
        reason="ok",
        policy_version="v1",
        evaluated_at=None,
        obligations=None,
    )

    data = decision.to_dict()

    assert data["evaluated_at"] is None


def test_to_deterministic_dict():

    decision = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.RESTRICT,
        reason="restricted",
        policy_version="v1",
        evaluated_at=datetime.utcnow(),
        obligations={"a": 1},
    )

    data = decision.to_deterministic_dict()

    assert data["outcome"] == "RESTRICT"
    assert data["reason"] == "restricted"


def test_direct_construction_blocked():

    fake_frame = type(
        "Frame",
        (),
        {"filename": "/tmp/not_allowed.py"},
    )()

    with patch(
        "inspect.stack",
        return_value=[fake_frame],
    ):
        with pytest.raises(
            RuntimeError,
            match="SecurityDecision must be created",
        ):
            SecurityDecision(
                outcome=DecisionOutcome.ALLOW,
                reason="x",
                policy_version="v1",
                evaluated_at=datetime.utcnow(),
            )