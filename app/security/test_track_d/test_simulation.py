# app/security/test_track_d/test_simulation.py

from unittest.mock import patch

from app.security.track_d.simulation import (
    simulate_decision
)
from app.security.decision import (
    SecurityDecision,
    DecisionOutcome,
)
from datetime import datetime

class DummyContext:
    pass


def test_simulation_allow():

    decision = SecurityDecision(
        outcome=DecisionOutcome.ALLOW,
        reason="allowed",
        policy_version="1.0.0",
        evaluated_at=datetime.utcnow(),
    )

    with patch(
        "app.security.track_d.simulation.SecurityPipeline"
    ) as pipeline:

        pipeline.return_value.evaluate.return_value = decision

        result = simulate_decision(
            DummyContext()
        )

        assert result.simulated_outcome == DecisionOutcome.ALLOW
        assert result.simulated_reason == "allowed"
        assert result.authoritative is False
        assert result.warnings["simulation_only"] is True


def test_simulation_deny_becomes_warn():

    decision = SecurityDecision(
        outcome=DecisionOutcome.DENY,
        reason="denied",
        policy_version="1.0.0",
        evaluated_at=datetime.utcnow(),
    )

    with patch(
        "app.security.track_d.simulation.SecurityPipeline"
    ) as pipeline:

        pipeline.return_value.evaluate.return_value = decision

        result = simulate_decision(
            DummyContext()
        )

        assert result.simulated_outcome == DecisionOutcome.RESTRICT
        assert result.simulated_reason == "denied"
        assert result.authoritative is False