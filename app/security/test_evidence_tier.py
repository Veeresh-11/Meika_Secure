from app.security.evidence.memory.tier import EvidenceTier


def test_hot_value():
    assert EvidenceTier.HOT.value == "hot"


def test_warm_value():
    assert EvidenceTier.WARM.value == "warm"


def test_cold_value():
    assert EvidenceTier.COLD.value == "cold"


def test_frozen_value():
    assert EvidenceTier.FROZEN.value == "frozen"


def test_enum_count():
    assert len(EvidenceTier) == 4


def test_enum_names():
    assert [tier.name for tier in EvidenceTier] == [
        "HOT",
        "WARM",
        "COLD",
        "FROZEN",
    ]