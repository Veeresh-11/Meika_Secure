# app/security/test_bootstrap.py

from unittest.mock import patch

from app.security.bootstrap import build_pipeline


def test_ci_environment_does_not_disable_signer():

    fake_policy = object()

    with patch(
        "app.security.bootstrap.load_policy",
        return_value=fake_policy,
    ):
        with patch.dict(
            "os.environ",
            {"CI_SECURITY_BYPASS": "1", "ENVIRONMENT": "test"},
            clear=False,
        ):
            kernel = build_pipeline()

    assert kernel.signer is not None
    assert kernel.graph is not None
    assert kernel.policy_evaluator is not None


def test_build_pipeline_normal_signer():

    fake_policy = object()

    fake_signer = object()

    with patch(
        "app.security.bootstrap.load_policy",
        return_value=fake_policy,
    ):
        with patch(
            "app.security.bootstrap.Ed25519LocalSigner",
            return_value=fake_signer,
        ):
            with patch.dict(
                "os.environ",
                {},
                clear=False,
            ):
                kernel = build_pipeline()

    assert kernel.signer is fake_signer
    assert kernel.graph is not None
    assert kernel.policy_evaluator is not None