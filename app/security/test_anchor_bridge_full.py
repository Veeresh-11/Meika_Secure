# app/security/test_anchor_bridge.py

from unittest.mock import Mock, patch

from app.security.evidence.anchor_bridge import (
    EvidenceAnchorBridge,
)


def test_anchor_normal_path():

    client = Mock()

    client.anchor.return_value = {
        "tx": "abc",
    }

    bridge = EvidenceAnchorBridge(client)

    result = bridge._anchor(
        "root123",
        5,
    )

    assert result == {
        "tx": "abc",
    }

    client.anchor.assert_called_once_with(
        "root123",
    )


def test_anchor_fallback_payload_path():

    client = Mock()

    client.anchor.side_effect = [
        TypeError(),
        {"tx": "fallback"},
    ]

    bridge = EvidenceAnchorBridge(client)

    result = bridge._anchor(
        "root123",
        7,
    )

    assert result == {
        "tx": "fallback",
    }

    assert client.anchor.call_count == 2

    client.anchor.assert_called_with(
        {
            "root_hash": "root123",
            "record_count": 7,
        }
    )


def test_seal_and_anchor():

    client = Mock()

    client.anchor.return_value = {
        "tx": "abc",
    }

    bridge = EvidenceAnchorBridge(client)

    fake_seal = {
        "snapshot": {
            "root_hash": "root123",
            "record_count": 5,
        }
    }

    with patch.object(
        bridge._seal_service,
        "seal",
        return_value=fake_seal,
    ):

        result = bridge.seal_and_anchor(
            records=[],
        )

    assert result["seal"] == fake_seal

    assert result["anchor_receipt"] == {
        "tx": "abc",
    }


def test_seal_anchor_and_record():

    client = Mock()

    bridge = EvidenceAnchorBridge(client)

    fake_result = {
        "seal": {
            "snapshot": {
                "root_hash": "root123",
                "record_count": 5,
            }
        },
        "anchor_receipt": {
            "tx": "abc",
        },
    }

    fake_record = object()

    store = Mock()

    with patch.object(
        bridge,
        "seal_and_anchor",
        return_value=fake_result,
    ):
        with patch(
            "app.security.evidence.anchor_bridge.build_anchor_record",
            return_value=fake_record,
        ):

            result = bridge.seal_anchor_and_record(
                records=[],
                store=store,
            )

    assert result == fake_result

    store.append.assert_called_once_with(
        fake_record,
    )