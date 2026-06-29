from app.security.device.posture import (
    DevicePostureEvaluator,
)


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


def test_missing_signals_false():

    evaluator = DevicePostureEvaluator()

    result = evaluator.evaluate({})

    assert result == {
        "secure_boot": False,
        "disk_encrypted": False,
        "os_up_to_date": False,
    }


def test_truthy_values_coerce():

    evaluator = DevicePostureEvaluator()

    result = evaluator.evaluate(
        {
            "secure_boot": 1,
            "disk_encrypted": "yes",
            "os_up_to_date": object(),
        }
    )

    assert result == {
        "secure_boot": True,
        "disk_encrypted": True,
        "os_up_to_date": True,
    }