from __future__ import annotations

from .static_provider import StaticTestnetProvider
from .base_provider import BaseAnchorProvider


class AnchorProviderFactory:

    @staticmethod
    def create(provider_type: str) -> BaseAnchorProvider:

        if provider_type == "STATIC":
            return StaticTestnetProvider()

        raise ValueError(f"Unknown anchor provider: {provider_type}")
