# app/security/federation/models.py

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class SigningKey:
    kid: str
    algorithm: str
    private_key: Any
    public_key: Any
    created_at: datetime
