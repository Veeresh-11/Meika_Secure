import pytest

from app.security.track_d.consensus.threshold_signature import (
    ThresholdSigner,
)


def test_threshold_signature_success():

    signer = ThresholdSigner.generate(
        total=5,
        threshold=3,
    )

    sig = signer.sign("abc123")

    assert sig.verify("abc123") is True


def test_threshold_signature_wrong_message():

    signer = ThresholdSigner.generate(
        total=5,
        threshold=3,
    )

    sig = signer.sign("abc123")

    assert sig.verify("different") is False


def test_threshold_cannot_exceed_total():

    with pytest.raises(
        ValueError,
        match="Threshold cannot exceed total",
    ):
        ThresholdSigner.generate(
            total=2,
            threshold=3,
        )


def test_governance_signer_id_exists():

    signer = ThresholdSigner.generate(
        total=3,
        threshold=2,
    )

    assert signer.governance_signer_id() is not None