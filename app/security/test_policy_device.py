from types import SimpleNamespace

from app.security.policy.evaluators.device import (
    match_device,
)



def test_no_device_no_device_rules():
    rule = SimpleNamespace(when={})
    ctx = SimpleNamespace(device=None)

    assert match_device(rule, ctx) is True


def test_no_device_with_device_rule():
    rule = SimpleNamespace(
        when={"device.registered": True}
    )

    ctx = SimpleNamespace(device=None)

    assert match_device(rule, ctx) is False


def test_device_registered_match():
    device = SimpleNamespace(
        registered=True,
        state="active",
    )

    rule = SimpleNamespace(
        when={"device.registered": True}
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is True


def test_device_registered_fail():
    device = SimpleNamespace(
        registered=False,
        state="active",
    )

    rule = SimpleNamespace(
        when={"device.registered": True}
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is False


def test_device_state_match():
    device = SimpleNamespace(
        registered=True,
        state="active",
    )

    rule = SimpleNamespace(
        when={"device.state": "active"}
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is True


def test_device_identity_mismatch():
    identity = SimpleNamespace(
        hardware_backed=False
    )

    device = SimpleNamespace(
        registered=True,
        state="active",
        identity=identity,
    )

    rule = SimpleNamespace(
        when={
            "device.identity.hardware_backed": True
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is False


def test_device_posture_mismatch():
    posture = SimpleNamespace(
        secure_boot=False
    )

    device = SimpleNamespace(
        registered=True,
        state="active",
        posture=posture,
    )

    rule = SimpleNamespace(
        when={
            "device.posture.secure_boot": True
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is False


def test_multiple_conditions_all_match():
    device = SimpleNamespace(
        registered=True,
        state="active",
    )

    rule = SimpleNamespace(
        when={
            "device.registered": True,
            "device.state": "active",
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is True
    
def test_identity_branch_failure():
    device = SimpleNamespace(
        identity=SimpleNamespace(
            hardware_backed=False
        )
    )

    rule = SimpleNamespace(
        when={
            "device.identity.hardware_backed": True
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is False


def test_posture_branch_failure():
    device = SimpleNamespace(
        posture=SimpleNamespace(
            secure_boot=False
        )
    )

    rule = SimpleNamespace(
        when={
            "device.posture.secure_boot": True
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is False


def test_unknown_device_key_fails_closed():
    device = SimpleNamespace()

    rule = SimpleNamespace(
        when={
            "device.some_future_field": True
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is False
    
def test_device_state_mismatch():
    device = SimpleNamespace(
        registered=True,
        state="inactive",
    )

    rule = SimpleNamespace(
        when={
            "device.state": "active"
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is False


def test_device_identity_match_continues():
    device = SimpleNamespace(
        identity=SimpleNamespace(
            hardware_backed=True
        ),
        registered=True,
        state="active",
    )

    rule = SimpleNamespace(
        when={
            "device.identity.hardware_backed": True,
            "device.state": "active",
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is True


def test_device_posture_match_continues():
    device = SimpleNamespace(
        posture=SimpleNamespace(
            secure_boot=True
        ),
        registered=True,
        state="active",
    )

    rule = SimpleNamespace(
        when={
            "device.posture.secure_boot": True,
            "device.state": "active",
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is True
    
def test_unknown_device_condition_after_valid_condition():
    device = SimpleNamespace(
        registered=True,
        state="active",
    )

    rule = SimpleNamespace(
        when={
            "device.registered": True,
            "device.some_future_field": True,
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is False
    
def test_unknown_device_condition_after_multiple_valid_conditions():
    device = SimpleNamespace(
        registered=True,
        state="active",
        identity=SimpleNamespace(
            hardware_backed=True
        ),
    )

    rule = SimpleNamespace(
        when={
            "device.registered": True,
            "device.identity.hardware_backed": True,
            "device.some_future_field": True,
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is False
    
def test_non_device_keys_are_ignored():
    device = SimpleNamespace(
        registered=True,
        state="active",
    )

    rule = SimpleNamespace(
        when={
            "authenticated": True,
            "risk_score": 50,
        }
    )

    ctx = SimpleNamespace(device=device)

    assert match_device(rule, ctx) is True