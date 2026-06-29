from app.security.runtime_state import KernelState


def test_normal_value():

    assert KernelState.NORMAL.value == "NORMAL"


def test_safe_mode_value():

    assert KernelState.SAFE_MODE.value == "SAFE_MODE"


def test_enum_count():

    assert len(KernelState) == 2