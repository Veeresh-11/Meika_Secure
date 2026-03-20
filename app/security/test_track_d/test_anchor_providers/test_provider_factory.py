import pytest
from app.security.track_d.anchoring.anchor_providers.provider_factory import (
    AnchorProviderFactory,
)


def test_factory_static():
    provider = AnchorProviderFactory.create("STATIC")
    assert provider.network_id() == "STATIC_TESTNET"


def test_factory_invalid():
    with pytest.raises(ValueError):
        AnchorProviderFactory.create("UNKNOWN")
