"""
TRACK D — Unified Provider Factory (Canonical)

Security Guarantees:
- Single provider creation path
- TrustStore-aware resolution
- Fail-closed behavior
- No silent fallback
- Hardware-root enforcement
"""

from __future__ import annotations
from typing import Dict, Optional

from .trust_store import TrustStore
from .hsm.software_provider import SoftwareProvider
from .hsm.pkcs11_provider import PKCS11Provider
from .hsm.base_provider import HSMProvider


class ProviderFactory:

    def __init__(
        self,
        trust_store: Optional[TrustStore] = None,
        hsm_config: Optional[Dict] = None,
    ):
        self._trust_store = trust_store
        self._hsm_config = hsm_config or {}
        self._cache: Dict[str, HSMProvider] = {}

    # ---------------------------------------------------------
    # Explicit Provider Creation
    # ---------------------------------------------------------

    def create_provider(self, provider_type: str) -> HSMProvider:

        if provider_type in self._cache:
            return self._cache[provider_type]

        if provider_type == "software":
            provider = SoftwareProvider()

        elif provider_type in ("hsm", "pkcs11"):
            provider = PKCS11Provider(self._hsm_config)

        else:
            raise ValueError("Unknown provider type")

        self._cache[provider_type] = provider
        return provider

    # ---------------------------------------------------------
    # TrustStore-Bound Provider Creation
    # ---------------------------------------------------------

    def create_provider_for_key(self, key_id: str) -> HSMProvider:

        if not self._trust_store:
            raise ValueError("TrustStore required for key-bound provider resolution")

        provider_type = self._trust_store.get_provider(key_id)

        provider = self.create_provider(provider_type)

        # 🚨 Hardware-root enforcement
        if self._trust_store.is_hardware_root(key_id):
            if not provider.is_hardware():
                raise ValueError("Hardware root must use hardware provider")

        return provider

