def verify_attestation(attestation: dict, expected_challenge: str) -> dict:
    if attestation.get("challenge") != expected_challenge:
        raise ValueError("Challenge mismatch")

    if not attestation.get("hardware_backed"):
        raise ValueError("Key not hardware-backed")

    if not attestation.get("attestation_verified"):
        raise ValueError("Attestation not verified")

    return {
        "public_key": attestation["public_key"],
        "attestation_type": attestation.get("type", "unknown"),
        "hardware_backed": True,
        "attestation_verified": True,
    }
