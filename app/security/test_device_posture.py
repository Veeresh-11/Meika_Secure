# app/security/test_device_posture.py

from app.security.device.posture import DevicePostureEvaluator


def test_all_signals_true():

    evaluator = DevicePostureEvaluator()

    result = evaluator.evaluate(
        {
            "secure_boot": True,
            "disk_encrypted": True,
            "os_up_to_date": True,
        }
    )

    assert result == {
        "secure_boot": True,
        "disk_encrypted": True,
        "os_up_to_date": True,
    }


def test_missing_signals_default_false():

    evaluator = DevicePostureEvaluator()

    result = evaluator.evaluate({})

    assert result == {
        "secure_boot": False,
        "disk_encrypted": False,
        "os_up_to_date": False,
    }


def test_falsy_values_become_false():

    evaluator = DevicePostureEvaluator()

    result = evaluator.evaluate(
        {
            "secure_boot": False,
            "disk_encrypted": 0,
            "os_up_to_date": None,
        }
    )

    assert result == {
        "secure_boot": False,
        "disk_encrypted": False,
        "os_up_to_date": False,
    }