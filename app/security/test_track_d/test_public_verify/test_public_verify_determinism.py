from app.security.track_d.public_verify.models import VerificationResponse


def test_verification_response_deterministic():

    r1 = VerificationResponse(
        verified=True,
        object_type="ROOT",
        object_id="abc",
        proof={"a": 1},
    ).to_dict()

    r2 = VerificationResponse(
        verified=True,
        object_type="ROOT",
        object_id="abc",
        proof={"a": 1},
    ).to_dict()

    # Ignore timestamp — check structure consistency
    r1.pop("timestamp")
    r2.pop("timestamp")

    assert r1 == r2
