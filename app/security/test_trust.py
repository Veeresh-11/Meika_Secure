import pytest

from app.security.trust import enforce_trust
from app.security.errors import SecurityPipelineError


class Device:
    pass


class Context:
    pass


def make_context(device):
    ctx = Context()
    ctx.device = device
    return ctx


def test_no_device_allowed():
    ctx = Context()
    ctx.device = None

    enforce_trust(ctx)


def test_clone_confirmed_denied():
    device = Device()
    device.clone_confirmed = True

    with pytest.raises(SecurityPipelineError):
        enforce_trust(make_context(device))


def test_clone_detected_denied():
    device = Device()
    device.clone_detected = True

    with pytest.raises(SecurityPipelineError):
        enforce_trust(make_context(device))


def test_is_clone_denied():
    device = Device()
    device.is_clone = True

    with pytest.raises(SecurityPipelineError):
        enforce_trust(make_context(device))


def test_cloned_state_denied():
    device = Device()
    device.state = "cloned"

    with pytest.raises(SecurityPipelineError):
        enforce_trust(make_context(device))


def test_compromised_device_denied():
    device = Device()
    device.compromised = True

    with pytest.raises(SecurityPipelineError):
        enforce_trust(make_context(device))


def test_clean_device_allowed():
    device = Device()
    device.clone_confirmed = False
    device.clone_detected = False
    device.is_clone = False
    device.compromised = False
    device.state = "active"

    enforce_trust(make_context(device))