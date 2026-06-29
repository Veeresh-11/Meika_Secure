from datetime import datetime, timedelta

from app.security.evidence.anchor_policy import (
    AnchorPolicy,
    TimeAnchorPolicy,
)


def test_record_threshold_hit():

    policy = AnchorPolicy(threshold=5)

    assert policy.should_anchor(5) is True
    assert policy.should_anchor(10) is True


def test_record_threshold_not_hit():

    policy = AnchorPolicy(threshold=5)

    assert policy.should_anchor(1) is False
    assert policy.should_anchor(4) is False
    assert policy.should_anchor(6) is False


def test_record_zero_never_anchors():

    policy = AnchorPolicy(threshold=5)

    assert policy.should_anchor(0) is False


def test_time_policy_first_call_true():

    policy = TimeAnchorPolicy(interval_seconds=60)

    assert policy.should_anchor() is True


def test_time_policy_interval_logic():

    policy = TimeAnchorPolicy(interval_seconds=60)

    policy.last_anchor_time = (
        datetime.utcnow() - timedelta(seconds=30)
    )

    assert policy.should_anchor() is False

    policy.last_anchor_time = (
        datetime.utcnow() - timedelta(seconds=61)
    )

    assert policy.should_anchor() is True


def test_mark_anchored_sets_timestamp():

    policy = TimeAnchorPolicy(interval_seconds=60)

    assert policy.last_anchor_time is None

    policy.mark_anchored()

    assert policy.last_anchor_time is not None