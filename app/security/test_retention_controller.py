from app.security.evidence.memory.retention import (
    EvidenceRetentionController,
)
from app.security.evidence.memory.tier import EvidenceTier


def test_default_tier_is_hot():

    controller = EvidenceRetentionController()

    assert (
        controller.get_tier("missing-hash")
        == EvidenceTier.HOT
    )


def test_transition_to_warm():

    controller = EvidenceRetentionController()

    controller.transition(
        "hash1",
        EvidenceTier.WARM,
    )

    assert (
        controller.get_tier("hash1")
        == EvidenceTier.WARM
    )


def test_transition_to_cold():

    controller = EvidenceRetentionController()

    controller.transition(
        "hash2",
        EvidenceTier.COLD,
    )

    assert (
        controller.get_tier("hash2")
        == EvidenceTier.COLD
    )


def test_transition_to_frozen():

    controller = EvidenceRetentionController()

    controller.transition(
        "hash3",
        EvidenceTier.FROZEN,
    )

    assert (
        controller.get_tier("hash3")
        == EvidenceTier.FROZEN
    )


def test_multiple_records_independent():

    controller = EvidenceRetentionController()

    controller.transition(
        "a",
        EvidenceTier.WARM,
    )

    controller.transition(
        "b",
        EvidenceTier.COLD,
    )

    assert controller.get_tier("a") == EvidenceTier.WARM
    assert controller.get_tier("b") == EvidenceTier.COLD