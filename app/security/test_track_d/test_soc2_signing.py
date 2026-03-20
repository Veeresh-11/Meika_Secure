from app.security.track_d.export_soc2 import generate_soc2_export, _canonical_json
from app.security.track_d.signing.ed25519_local import Ed25519LocalSigner


def _sample_evidence():
    return [
        {"sequence": 0, "record_hash": "a" * 64},
        {"sequence": 1, "record_hash": "b" * 64},
    ]


def _control_mapping():
    return {"SOC2_CC6.1": ["AUTH_DECISION"]}


def test_signed_export_contains_signature_fields():
    signer = Ed25519LocalSigner()

    export = generate_soc2_export(
        evidence_records=_sample_evidence(),
        kernel_version="1.0.0",
        export_period={"start": "2026-01-01", "end": "2026-03-31"},
        control_mapping=_control_mapping(),
        signer=signer,
    )

    assert "signature" in export
    assert "signing_algorithm" in export
    assert "key_id" in export


def test_signature_verifies():
    signer = Ed25519LocalSigner()

    export = generate_soc2_export(
        evidence_records=_sample_evidence(),
        kernel_version="1.0.0",
        export_period={"start": "2026-01-01", "end": "2026-03-31"},
        control_mapping=_control_mapping(),
        signer=signer,
    )

    signature = export["signature"]

    payload = dict(export)
    payload.pop("signature")
    payload.pop("bundle_hash")
    payload.pop("signing_algorithm")
    payload.pop("key_id")

    canonical = _canonical_json(payload)

    assert signer.verify(canonical, signature)
