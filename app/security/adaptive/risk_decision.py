from dataclasses import dataclass


@dataclass(frozen=True)
class RiskDecision:
    score: int
    action: str
    reasons: list[str]