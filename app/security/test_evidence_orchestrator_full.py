# app/security/test_evidence_orchestrator_full.py

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.security.evidence_orchestrator import (
    EvidenceEnforcedPipeline,
)
from app.security.decision import (
    SecurityDecisionFactory,
    DecisionOutcome,
)
from app.security.errors import SecurityInvariantViolation


def make_decision(outcome):
    return SecurityDecisionFactory._kernel_create(
        outcome=outcome,
        reason="test",
        policy_version="v1",
        evaluated_at=datetime.utcnow(),
        obligations=None,
        evidence_hash=None,
    )


# =====================================================
# _default_context
# =====================================================

def test_default_context():
    pipeline = EvidenceEnforcedPipeline()

    ctx = pipeline._default_context()

    assert ctx.request_id == "kernel-test"
    assert ctx.principal_id == "kernel"
    assert ctx.authenticated is True


# =====================================================
# DENY branch
# =====================================================

def test_evaluate_returns_deny_immediately():
    pipeline = EvidenceEnforcedPipeline()

    pipeline.kernel = Mock()
    pipeline.kernel.evaluate.return_value = make_decision(
        DecisionOutcome.DENY
    )

    result = pipeline.evaluate(Mock())

    assert result.outcome == DecisionOutcome.DENY


# =====================================================
# receipt None invariant
# =====================================================

def test_allow_without_receipt_raises(monkeypatch):
    pipeline = EvidenceEnforcedPipeline()

    pipeline.kernel = Mock()
    pipeline.kernel.evaluate.return_value = make_decision(
        DecisionOutcome.ALLOW
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.build_evidence_record",
        lambda **kwargs: "record",
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.append_evidence_record",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(SecurityInvariantViolation):
        pipeline.evaluate(Mock())


# =====================================================
# happy path
# =====================================================

def test_allow_generates_evidence_hash(monkeypatch):
    pipeline = EvidenceEnforcedPipeline()

    pipeline.kernel = Mock()
    pipeline.kernel.evaluate.return_value = make_decision(
        DecisionOutcome.ALLOW
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.build_evidence_record",
        lambda **kwargs: "record",
    )

    receipt = SimpleNamespace(
        merkle_root="ROOT123"
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.append_evidence_record",
        lambda *args, **kwargs: receipt,
    )

    result = pipeline.evaluate(Mock())

    assert result.evidence_hash == "ROOT123"


# =====================================================
# event emitter success
# =====================================================

def test_event_emitter_success(monkeypatch):
    emitter = Mock()

    pipeline = EvidenceEnforcedPipeline(
        event_emitter=emitter
    )

    pipeline.kernel = Mock()
    pipeline.kernel.evaluate.return_value = make_decision(
        DecisionOutcome.ALLOW
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.build_evidence_record",
        lambda **kwargs: "record",
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.append_evidence_record",
        lambda *args, **kwargs: SimpleNamespace(
            merkle_root="ROOT"
        ),
    )

    pipeline.evaluate(Mock())

    emitter.emit.assert_called_once()


# =====================================================
# event emitter exception swallowed
# =====================================================

def test_event_emitter_exception_swallowed(monkeypatch):
    emitter = Mock()
    emitter.emit.side_effect = RuntimeError()

    pipeline = EvidenceEnforcedPipeline(
        event_emitter=emitter
    )

    pipeline.kernel = Mock()
    pipeline.kernel.evaluate.return_value = make_decision(
        DecisionOutcome.ALLOW
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.build_evidence_record",
        lambda **kwargs: "record",
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.append_evidence_record",
        lambda *args, **kwargs: SimpleNamespace(
            merkle_root="ROOT"
        ),
    )

    result = pipeline.evaluate(Mock())

    assert result.evidence_hash == "ROOT"


# =====================================================
# simulation success
# =====================================================

def test_simulation_success(monkeypatch):
    simulation_engine = Mock()
    simulation_engine.evaluate.return_value = ["result"]

    simulation_emitter = Mock()

    pipeline = EvidenceEnforcedPipeline(
        simulation_engine=simulation_engine,
        simulation_emitter=simulation_emitter,
    )

    pipeline.kernel = Mock()
    pipeline.kernel.evaluate.return_value = make_decision(
        DecisionOutcome.ALLOW
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.build_evidence_record",
        lambda **kwargs: "record",
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.append_evidence_record",
        lambda *args, **kwargs: SimpleNamespace(
            merkle_root="ROOT"
        ),
    )

    pipeline.evaluate(Mock())

    simulation_engine.evaluate.assert_called_once()
    simulation_emitter.emit.assert_called_once_with(
        ["result"]
    )


# =====================================================
# simulation exception swallowed
# =====================================================

def test_simulation_exception_swallowed(monkeypatch):
    simulation_engine = Mock()
    simulation_engine.evaluate.side_effect = RuntimeError()

    simulation_emitter = Mock()

    pipeline = EvidenceEnforcedPipeline(
        simulation_engine=simulation_engine,
        simulation_emitter=simulation_emitter,
    )

    pipeline.kernel = Mock()
    pipeline.kernel.evaluate.return_value = make_decision(
        DecisionOutcome.ALLOW
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.build_evidence_record",
        lambda **kwargs: "record",
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.append_evidence_record",
        lambda *args, **kwargs: SimpleNamespace(
            merkle_root="ROOT"
        ),
    )

    result = pipeline.evaluate(Mock())

    assert result.evidence_hash == "ROOT"
    
def test_simulation_without_emitter(monkeypatch):
    from types import SimpleNamespace

    simulation_engine = Mock()
    simulation_engine.evaluate.return_value = ["result"]

    pipeline = EvidenceEnforcedPipeline(
        simulation_engine=simulation_engine,
        simulation_emitter=None,
    )

    pipeline.kernel = Mock()
    pipeline.kernel.evaluate.return_value = make_decision(
        DecisionOutcome.ALLOW
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.build_evidence_record",
        lambda **kwargs: "record",
    )

    monkeypatch.setattr(
        "app.security.evidence_orchestrator.evidence_engine.append_evidence_record",
        lambda *args, **kwargs: SimpleNamespace(
            merkle_root="ROOT"
        ),
    )

    result = pipeline.evaluate(Mock())

    assert result.evidence_hash == "ROOT"
    simulation_engine.evaluate.assert_called_once()