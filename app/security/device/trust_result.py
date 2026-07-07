from dataclasses import dataclass


@dataclass(frozen=True)
class TrustResult:
    """
    Immutable output of the Device Trust Engine.
    """

    score: int

    trust_level: str

    risk_level: str

    reasons: tuple[str, ...]