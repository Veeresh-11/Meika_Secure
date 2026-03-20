def revoke_device_identity(device: dict, reason: str):
    device["identity"]["revoked"] = True
    device["identity"]["revocation_reason"] = reason
