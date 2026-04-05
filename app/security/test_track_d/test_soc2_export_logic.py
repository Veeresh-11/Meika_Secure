from copy import deepcopy
import pytest

from app.security.track_d.export_soc2 import generate_soc2_export


def _sample_evidence():
    """
    Minimal, storage-agnostic evidence records.
    Track-D treats these as opaque blobs.
    """
    return [
        {"sequence": 0, "record_hash": "a" * 64},
        {"sequence": 1, "record_hash": "b" * 64},
        {"sequence": 2, "record_hash": "c" * 64},
    ]


def _control_mapping():
    return {
        "SOC2_CC6.1": ["AUTH_DECISION"],
        "SOC2_CC7.2": ["DEVICE_TRUST"],
    }


def test_soc2_export_is_deterministic():
    evidence = _sample_evidence()
    controls = _control_mapping()

    export1 = generate_soc2_export(
        evidence_records=deepcopy(evidence),
        kernel_version="1.0.0",
        export_period={
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-03-31T23:59:59Z",
        },
        control_mapping=controls,
    )

    export2 = generate_soc2_export(
        evidence_records=deepcopy(evidence),
        kernel_version="1.0.0",
        export_period={
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-03-31T23:59:59Z",
        },
        control_mapping=controls,
    )

    # Deterministic core guarantee
    assert export1["bundle_hash"] == export2["bundle_hash"]

    # Remove NON-deterministic crypto fields
    export1_clean = dict(export1)
    export2_clean = dict(export2)

    export1_clean.pop("signature", None)
    export2_clean.pop("signature", None)

    export1_clean.pop("key_id", None)
    export2_clean.pop("key_id", None)

    # Now compare deterministic structure
    assert export1_clean == export2_clean


def test_soc2_export_preserves_evidence_order():
    evidence = _sample_evidence()

    export = generate_soc2_export(
        evidence_records=evidence,
        kernel_version="1.0.0",
        export_period={
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-03-31T23:59:59Z",
        },
        control_mapping={},
    )

    sequences = [r["sequence"] for r in export["records"]]
    assert sequences == [0, 1, 2]


def test_soc2_export_fails_on_empty_evidence():
    with pytest.raises(ValueError):
        generate_soc2_export(
            evidence_records=[],
            kernel_version="1.0.0",
            export_period={
                "start": "2026-01-01T00:00:00Z",
                "end": "2026-03-31T23:59:59Z",
            },
            control_mapping={},
        )


def test_soc2_export_does_not_mutate_input():
    evidence = _sample_evidence()
    original = deepcopy(evidence)

    generate_soc2_export(
        evidence_records=evidence,
        kernel_version="1.0.0",
        export_period={
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-03-31T23:59:59Z",
        },
        control_mapping={},
    )

    assert evidence == original