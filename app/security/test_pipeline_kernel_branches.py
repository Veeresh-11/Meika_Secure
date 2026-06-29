from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.security.pipeline import SecureIDKernel
from app.security.context import SecurityContext
from app.security.errors import (
    SecurityPipelineError,
    FailureClass,
    SecurityInvariantViolation,
)
from app.security.results import DenyReason
from app.security.decision import (
    DecisionOutcome,
    SecurityDecisionFactory,
)
from app.security.runtime_state import KernelState
from app.security.version import KERNEL_VERSION
from app.security.pipeline import (SecurityPipeline)

def ctx():
    return SecurityContext(
        request_id="1",
        principal_id="kernel",
        intent="authentication.attempt",
        authenticated=True,
        device=None,
        device_id=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
        grant=None,
    )


def valid_context():

    return SecurityContext(
        request_id="1",
        principal_id="user",
        intent="authentication.attempt",
        authenticated=True,
        device=None,
        device_id=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
        grant=None,
    )


# -------------------------------------------------
# SAFE MODE allow -> governance deny
# -------------------------------------------------

def test_safe_mode_blocks_allow():

    kernel = SecureIDKernel()

    
    kernel._state = KernelState.SAFE_MODE

    with patch(
        "app.security.pipeline.SecurityPipeline.evaluate"
    ) as parent:

        parent.return_value = SecurityDecisionFactory._kernel_create(
            outcome=DecisionOutcome.ALLOW,
            reason=DenyReason.DEFAULT_DENY,
            policy_version=KERNEL_VERSION,
            evaluated_at=datetime.utcnow(),
            obligations={},
        )

        with pytest.raises(SecurityPipelineError):
            kernel.evaluate(ctx())


# -------------------------------------------------
# SecurityPipelineError -> deny normalization
# -------------------------------------------------

def test_pipeline_error_normalized():

    kernel = SecureIDKernel()

    with patch(
        "app.security.pipeline.SecurityPipeline.evaluate",
        side_effect=SecurityPipelineError(
            DenyReason.DEFAULT_DENY,
            FailureClass.POLICY,
        ),
    ):
        decision = kernel.evaluate(ctx())

    assert decision.outcome == DecisionOutcome.DENY


# -------------------------------------------------
# metrics failure ignored
# -------------------------------------------------

def test_decision_metric_failure():

    kernel = SecureIDKernel()

    with patch(
        "app.security.pipeline.metrics.inc",
        side_effect=Exception(),
    ):
        decision = kernel.evaluate(ctx())

    assert decision is not None


# -------------------------------------------------
# policy version mismatch
# -------------------------------------------------

def test_policy_version_mismatch():

    kernel = SecureIDKernel()

    with patch(
        "app.security.pipeline.SecurityPipeline.evaluate"
    ) as parent:

        parent.return_value = SecurityDecisionFactory._kernel_create(
            outcome=DecisionOutcome.DENY,
            reason=DenyReason.DEFAULT_DENY,
            policy_version="BAD_VERSION",
            evaluated_at=datetime.utcnow(),
            obligations={},
        )

        with pytest.raises(SecurityInvariantViolation):
            kernel.evaluate(ctx())


# -------------------------------------------------
# build hash mismatch
# -------------------------------------------------

def test_build_hash_mismatch():

    kernel = SecureIDKernel()

    kernel._build_hash = "CORRUPTED"

    with pytest.raises(SecurityInvariantViolation):
        kernel.evaluate(ctx())


# -------------------------------------------------
# AttributeError evidence path
# -------------------------------------------------

def test_evidence_attribute_error_path():

    kernel = SecureIDKernel()

    allow = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.ALLOW,
        reason=DenyReason.DEFAULT_DENY,
        policy_version=KERNEL_VERSION,
        evaluated_at=datetime.utcnow(),
        obligations={},
    )

    with patch(
        "app.security.pipeline.SecurityPipeline.evaluate",
        return_value=allow,
    ):
        with patch(
            "app.security.pipeline.evidence_engine.build_evidence_record",
            side_effect=AttributeError(),
        ):
            decision = kernel.evaluate(ctx())

    assert decision.reason == DenyReason.MISSING_EVIDENCE


# -------------------------------------------------
# Generic evidence exception
# -------------------------------------------------

def test_evidence_commit_failure():

    kernel = SecureIDKernel()

    allow = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.ALLOW,
        reason=DenyReason.DEFAULT_DENY,
        policy_version=KERNEL_VERSION,
        evaluated_at=datetime.utcnow(),
        obligations={},
    )

    with patch(
        "app.security.pipeline.SecurityPipeline.evaluate",
        return_value=allow,
    ):
        with patch(
            "app.security.pipeline.evidence_engine.build_evidence_record",
            side_effect=RuntimeError(),
        ):
            with pytest.raises(SecurityInvariantViolation):
                kernel.evaluate(ctx())


# -------------------------------------------------
# evidence metrics failure
# -------------------------------------------------

def test_evidence_metrics_failure():

    kernel = SecureIDKernel()

    receipt = SimpleNamespace(
        merkle_root="root",
        record_hash="hash",
    )

    allow = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.ALLOW,
        reason=DenyReason.DEFAULT_DENY,
        policy_version=KERNEL_VERSION,
        evaluated_at=datetime.utcnow(),
        obligations={},
    )

    with patch(
        "app.security.pipeline.SecurityPipeline.evaluate",
        return_value=allow,
    ):
        with patch(
            "app.security.pipeline.evidence_engine.build_evidence_record",
            return_value=object(),
        ):
            with patch(
                "app.security.pipeline.evidence_engine.append_evidence_record",
                return_value=receipt,
            ):
                with patch(
                    "app.security.pipeline.metrics.inc",
                    side_effect=Exception(),
                ):
                    decision = kernel.evaluate(ctx())

    assert decision.evidence_hash == "root"


# -------------------------------------------------
# receipt generation
# -------------------------------------------------

def test_authorization_receipt_attached():

    kernel = SecureIDKernel()

    kernel.signer = object()

    receipt = SimpleNamespace(
        merkle_root="root",
        record_hash="hash",
    )

    auth_receipt = {"ok": True}

    allow = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.ALLOW,
        reason=DenyReason.DEFAULT_DENY,
        policy_version=KERNEL_VERSION,
        evaluated_at=datetime.utcnow(),
        obligations={},
    )

    with patch(
        "app.security.pipeline.SecurityPipeline.evaluate",
        return_value=allow,
    ):
        with patch(
            "app.security.pipeline.evidence_engine.build_evidence_record",
            return_value=object(),
        ):
            with patch(
                "app.security.pipeline.evidence_engine.append_evidence_record",
                return_value=receipt,
            ):
                with patch(
                    "app.security.pipeline.AuthorizationReceiptGenerator"
                ) as gen:

                    gen.return_value.generate.return_value = auth_receipt

                    decision = kernel.evaluate(ctx())

    assert decision.evidence_hash == "root"


# -------------------------------------------------
# receipt generation failure ignored
# -------------------------------------------------

def test_authorization_receipt_failure_ignored():

    kernel = SecureIDKernel()

    kernel.signer = object()

    receipt = SimpleNamespace(
        merkle_root="root",
        record_hash="hash",
    )

    allow = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.ALLOW,
        reason=DenyReason.DEFAULT_DENY,
        policy_version=KERNEL_VERSION,
        evaluated_at=datetime.utcnow(),
        obligations={},
    )

    with patch(
        "app.security.pipeline.SecurityPipeline.evaluate",
        return_value=allow,
    ):
        with patch(
            "app.security.pipeline.evidence_engine.build_evidence_record",
            return_value=object(),
        ):
            with patch(
                "app.security.pipeline.evidence_engine.append_evidence_record",
                return_value=receipt,
            ):
                with patch(
                    "app.security.pipeline.AuthorizationReceiptGenerator",
                    side_effect=Exception(),
                ):
                    decision = kernel.evaluate(ctx())

    assert decision.evidence_hash == "root"
    
def test_default_policy_deny_when_no_device():

    pipeline = SecurityPipeline()

    ctx = valid_context()

    from dataclasses import replace

    ctx = replace(
        ctx,
        device=None,
    )

    decision = pipeline._default_policy(ctx)

    assert decision.outcome == DecisionOutcome.DENY
    
def test_dict_device_conversion_branch():

    pipeline = SecurityPipeline()

    ctx = valid_context()

    object.__setattr__(
        ctx,
        "device",
        {
            "device_id": "x",
            "registered": True,
            "compromised": False,
            "clone_confirmed": False,
            "state": "active",
            "hardware_backed": True,
            "attestation_verified": True,
            "binding_valid": True,
            "replay_detected": False,
            "secure_boot": True,
        },
    )

    decision = pipeline.evaluate(ctx)

    assert decision is not None
    
    
def test_governance_revoked_branch():

    class Revoked:
        def is_revoked(self, version):
            return True

    pipeline = SecurityPipeline(
        revocation_registry=Revoked()
    )

    with pytest.raises(SecurityPipelineError):
        pipeline.evaluate(valid_context())
        
def test_deny_normalization_branch():

    def deny_policy(ctx):
        return SecurityDecisionFactory._kernel_create(
            outcome=DecisionOutcome.DENY,
            reason=DenyReason.POLICY_DENY,
            policy_version=KERNEL_VERSION,
            evaluated_at=ctx.request_time,
            obligations={"x": "y"},
        )

    pipeline = SecurityPipeline(
        policy_evaluator=deny_policy
    )

    decision = pipeline.evaluate(
        valid_context()
    )

    assert decision.outcome == DecisionOutcome.DENY
    assert "evidence" in decision.obligations
    
def test_enter_safe_mode_already_safe():

    kernel = SecureIDKernel()

    kernel._state = KernelState.SAFE_MODE

    kernel._enter_safe_mode("again")

    assert kernel._state == KernelState.SAFE_MODE
    
def test_safe_mode_returns_deny():

    kernel = SecureIDKernel()

    kernel._state = KernelState.SAFE_MODE

    deny = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.DENY,
        reason=DenyReason.POLICY_DENY,
        policy_version=KERNEL_VERSION,
        evaluated_at=datetime.utcnow(),
        obligations={"evidence": {}},
    )

    with patch(
        "app.security.pipeline.SecurityPipeline.evaluate",
        return_value=deny,
    ):
        decision = kernel.evaluate(ctx())

    assert decision.outcome == DecisionOutcome.DENY
    
def test_kernel_returns_non_allow():

    kernel = SecureIDKernel()

    deny = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.DENY,
        reason=DenyReason.POLICY_DENY,
        policy_version=KERNEL_VERSION,
        evaluated_at=datetime.utcnow(),
        obligations={"evidence": {}},
    )

    with patch(
        "app.security.pipeline.SecurityPipeline.evaluate",
        return_value=deny,
    ):
        decision = kernel.evaluate(ctx())

    assert decision.outcome == DecisionOutcome.DENY
    
def test_evidence_append_none_receipt():

    kernel = SecureIDKernel()

    allow = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.ALLOW,
        reason="ALLOW",
        policy_version=KERNEL_VERSION,
        evaluated_at=datetime.utcnow(),
        obligations={},
    )

    with patch(
        "app.security.pipeline.SecurityPipeline.evaluate",
        return_value=allow,
    ):
        with patch(
            "app.security.pipeline.evidence_engine.build_evidence_record",
            return_value=object(),
        ):
            with patch(
                "app.security.pipeline.evidence_engine.append_evidence_record",
                return_value=None,
            ):
                with pytest.raises(
                    SecurityInvariantViolation
                ):
                    kernel.evaluate(ctx())
                    
from unittest.mock import patch
from types import SimpleNamespace

def test_object_device_fallback_branch():

    pipeline = SecurityPipeline()

    ctx = valid_context()

    fake_device = SimpleNamespace(
        device_id="dev1",
        registered=True,
        compromised=False,
        clone_confirmed=False,
        state="active",
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        replay_detected=False,
        secure_boot=True,
    )

    object.__setattr__(ctx, "device", fake_device)

    with patch(
        "app.security.pipeline.DeviceTrustEvaluator.enforce"
    ) as trust:

        decision = pipeline.evaluate(ctx)

    trust.assert_called_once()

    assert decision is not None
    
from datetime import datetime

class ValidGrant:
    def __init__(self, intent, expires_at):
        self.intent = intent
        self.expires_at = expires_at

    def to_dict(self):
        return {
            "intent": self.intent,
            "expires_at": self.expires_at.isoformat(),
        }


def test_grant_intent_match_continues():

    pipeline = SecurityPipeline()

    ctx = valid_context()

    grant = ValidGrant(
        intent=ctx.intent,
        expires_at=ctx.request_time.replace(year=2099),
    )

    object.__setattr__(
        ctx,
        "grant",
        grant,
    )

    decision = pipeline.evaluate(ctx)

    assert decision is not None